// Does a Vulkan host import of MEM_WRITE_WATCH memory keep GetWriteWatch honest on Windows?
// Reports pages GetWriteWatch sees as written after: the import, a GPU read (copy out), a GPU write (fill), a CPU store.
#define VK_NO_PROTOTYPES
#include <vulkan/vulkan.h>
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>

static PFN_vkGetInstanceProcAddr gipa;
static VkInstance inst;
static VkDevice dev;
#define IFN(n) auto n = reinterpret_cast<PFN_##n>(gipa(inst, #n))
#define DFN(n) auto n = reinterpret_cast<PFN_##n>(gipa(inst, #n))

static int fail(const char* what, VkResult r) { std::printf("FAIL %s (%d)\n", what, static_cast<int>(r)); return 1; }

int main(int argc, char** argv) {
    const int pagesWanted = argc > 1 ? std::atoi(argv[1]) : 16;
    HMODULE lib = LoadLibraryA("vulkan-1.dll");
    if (!lib) { std::puts("FAIL vulkan-1.dll"); return 1; }
    gipa = reinterpret_cast<PFN_vkGetInstanceProcAddr>(GetProcAddress(lib, "vkGetInstanceProcAddr"));
    auto vkCreateInstance = reinterpret_cast<PFN_vkCreateInstance>(gipa(nullptr, "vkCreateInstance"));
    VkApplicationInfo app{VK_STRUCTURE_TYPE_APPLICATION_INFO};
    app.apiVersion = VK_API_VERSION_1_1;
    VkInstanceCreateInfo ici{VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO};
    ici.pApplicationInfo = &app;
    VkResult r = vkCreateInstance(&ici, nullptr, &inst);
    if (r != VK_SUCCESS) return fail("vkCreateInstance", r);
    IFN(vkEnumeratePhysicalDevices); IFN(vkGetPhysicalDeviceProperties); IFN(vkGetPhysicalDeviceProperties2);
    IFN(vkGetPhysicalDeviceQueueFamilyProperties); IFN(vkCreateDevice); IFN(vkGetPhysicalDeviceMemoryProperties);
    std::uint32_t count = 0;
    vkEnumeratePhysicalDevices(inst, &count, nullptr);
    std::vector<VkPhysicalDevice> pds(count);
    vkEnumeratePhysicalDevices(inst, &count, pds.data());
    VkPhysicalDevice pd = VK_NULL_HANDLE;
    for (auto p : pds) { VkPhysicalDeviceProperties pr; vkGetPhysicalDeviceProperties(p, &pr); if (pr.deviceType == VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU) { pd = p; std::printf("device %s, driver %u.%u\n", pr.deviceName, (pr.driverVersion >> 22) & 0x3ff, (pr.driverVersion >> 14) & 0xff); break; } }
    if (!pd) { std::puts("FAIL no discrete GPU"); return 1; }
    VkPhysicalDeviceExternalMemoryHostPropertiesEXT hostProps{VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_EXTERNAL_MEMORY_HOST_PROPERTIES_EXT};
    VkPhysicalDeviceProperties2 props2{VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROPERTIES_2, &hostProps};
    vkGetPhysicalDeviceProperties2(pd, &props2);
    const std::uint64_t align = hostProps.minImportedHostPointerAlignment;
    std::printf("minImportedHostPointerAlignment %llu\n", static_cast<unsigned long long>(align));
    vkGetPhysicalDeviceQueueFamilyProperties(pd, &count, nullptr);
    std::vector<VkQueueFamilyProperties> qf(count);
    vkGetPhysicalDeviceQueueFamilyProperties(pd, &count, qf.data());
    std::uint32_t family = 0;
    for (std::uint32_t i = 0; i < count; ++i) if (qf[i].queueFlags & VK_QUEUE_GRAPHICS_BIT) { family = i; break; }
    float prio = 1.0f;
    VkDeviceQueueCreateInfo qci{VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO};
    qci.queueFamilyIndex = family; qci.queueCount = 1; qci.pQueuePriorities = &prio;
    const char* exts[] = {VK_EXT_EXTERNAL_MEMORY_HOST_EXTENSION_NAME};
    VkDeviceCreateInfo dci{VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO};
    dci.queueCreateInfoCount = 1; dci.pQueueCreateInfos = &qci; dci.enabledExtensionCount = 1; dci.ppEnabledExtensionNames = exts;
    if ((r = vkCreateDevice(pd, &dci, nullptr, &dev)) != VK_SUCCESS) return fail("vkCreateDevice", r);
    DFN(vkGetDeviceQueue); DFN(vkGetMemoryHostPointerPropertiesEXT); DFN(vkCreateBuffer); DFN(vkGetBufferMemoryRequirements);
    DFN(vkAllocateMemory); DFN(vkBindBufferMemory); DFN(vkCreateCommandPool); DFN(vkAllocateCommandBuffers);
    DFN(vkBeginCommandBuffer); DFN(vkEndCommandBuffer); DFN(vkCmdCopyBuffer); DFN(vkCmdFillBuffer); DFN(vkQueueSubmit);
    DFN(vkQueueWaitIdle); DFN(vkResetCommandBuffer); DFN(vkDestroyDevice); DFN(vkFreeMemory); DFN(vkDestroyBuffer);
    VkQueue queue; vkGetDeviceQueue(dev, family, 0, &queue);

    const std::uint64_t page = 4096;
    const std::uint64_t bytes = ((pagesWanted * page) + align - 1) / align * align;
    const std::size_t pages = static_cast<std::size_t>(bytes / page);
    auto* raw = static_cast<std::uint8_t*>(VirtualAlloc(nullptr, bytes + align, MEM_RESERVE | MEM_COMMIT | MEM_WRITE_WATCH, PAGE_READWRITE));
    if (!raw) { std::printf("FAIL VirtualAlloc %lu\n", GetLastError()); return 1; }
    auto* base = reinterpret_cast<std::uint8_t*>((reinterpret_cast<std::uintptr_t>(raw) + align - 1) / align * align);
    for (std::size_t i = 0; i < pages; ++i) base[i * page] = 1;
    std::vector<void*> hits(pages);
    const auto collect = [&](const char* what) {
        ULONG_PTR n = pages; DWORD gran = 0;
        const UINT rc = GetWriteWatch(WRITE_WATCH_FLAG_RESET, base, bytes, hits.data(), &n, &gran);
        std::printf("%-28s %s %llu of %zu pages\n", what, rc == 0 ? "written:" : "GetWriteWatch FAILED", static_cast<unsigned long long>(n), pages);
        return static_cast<unsigned long long>(n);
    };
    collect("before import (reset)");

    VkMemoryHostPointerPropertiesEXT hpp{VK_STRUCTURE_TYPE_MEMORY_HOST_POINTER_PROPERTIES_EXT};
    if ((r = vkGetMemoryHostPointerPropertiesEXT(dev, VK_EXTERNAL_MEMORY_HANDLE_TYPE_HOST_ALLOCATION_BIT_EXT, base, &hpp)) != VK_SUCCESS) return fail("vkGetMemoryHostPointerPropertiesEXT", r);
    VkExternalMemoryBufferCreateInfo ext{VK_STRUCTURE_TYPE_EXTERNAL_MEMORY_BUFFER_CREATE_INFO};
    ext.handleTypes = VK_EXTERNAL_MEMORY_HANDLE_TYPE_HOST_ALLOCATION_BIT_EXT;
    VkBufferCreateInfo bci{VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO, &ext};
    bci.size = bytes; bci.usage = VK_BUFFER_USAGE_TRANSFER_SRC_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT | VK_BUFFER_USAGE_STORAGE_BUFFER_BIT;
    VkBuffer imported; if ((r = vkCreateBuffer(dev, &bci, nullptr, &imported)) != VK_SUCCESS) return fail("vkCreateBuffer import", r);
    VkMemoryRequirements req; vkGetBufferMemoryRequirements(dev, imported, &req);
    std::uint32_t type = 0; const std::uint32_t bits = req.memoryTypeBits & hpp.memoryTypeBits;
    while (type < 32 && !(bits & (1u << type))) ++type;
    VkImportMemoryHostPointerInfoEXT imp{VK_STRUCTURE_TYPE_IMPORT_MEMORY_HOST_POINTER_INFO_EXT};
    imp.handleType = VK_EXTERNAL_MEMORY_HANDLE_TYPE_HOST_ALLOCATION_BIT_EXT; imp.pHostPointer = base;
    VkMemoryAllocateInfo mai{VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO, &imp};
    mai.allocationSize = bytes; mai.memoryTypeIndex = type;
    VkDeviceMemory importedMemory;
    if ((r = vkAllocateMemory(dev, &mai, nullptr, &importedMemory)) != VK_SUCCESS) return fail("vkAllocateMemory import (MEM_WRITE_WATCH memory)", r);
    vkBindBufferMemory(dev, imported, importedMemory, 0);
    std::puts("import of MEM_WRITE_WATCH memory: ok");
    collect("after import");

    VkBufferCreateInfo dbi{VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO};
    dbi.size = bytes; dbi.usage = VK_BUFFER_USAGE_TRANSFER_DST_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT;
    VkBuffer devBuf; vkCreateBuffer(dev, &dbi, nullptr, &devBuf);
    VkMemoryRequirements dreq; vkGetBufferMemoryRequirements(dev, devBuf, &dreq);
    VkPhysicalDeviceMemoryProperties mp; vkGetPhysicalDeviceMemoryProperties(pd, &mp);
    std::uint32_t dtype = 0;
    for (; dtype < mp.memoryTypeCount; ++dtype) if ((dreq.memoryTypeBits & (1u << dtype)) && (mp.memoryTypes[dtype].propertyFlags & VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT)) break;
    VkMemoryAllocateInfo dai{VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO}; dai.allocationSize = dreq.size; dai.memoryTypeIndex = dtype;
    VkDeviceMemory devMem; vkAllocateMemory(dev, &dai, nullptr, &devMem); vkBindBufferMemory(dev, devBuf, devMem, 0);

    VkCommandPoolCreateInfo cpi{VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO}; cpi.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT; cpi.queueFamilyIndex = family;
    VkCommandPool pool; vkCreateCommandPool(dev, &cpi, nullptr, &pool);
    VkCommandBufferAllocateInfo cai{VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO}; cai.commandPool = pool; cai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY; cai.commandBufferCount = 1;
    VkCommandBuffer cb; vkAllocateCommandBuffers(dev, &cai, &cb);
    const auto submit = [&](auto record) {
        vkResetCommandBuffer(cb, 0);
        VkCommandBufferBeginInfo bi{VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO};
        vkBeginCommandBuffer(cb, &bi); record(); vkEndCommandBuffer(cb);
        VkSubmitInfo si{VK_STRUCTURE_TYPE_SUBMIT_INFO}; si.commandBufferCount = 1; si.pCommandBuffers = &cb;
        vkQueueSubmit(queue, 1, &si, VK_NULL_HANDLE); vkQueueWaitIdle(queue);
    };
    VkBufferCopy region{0, 0, bytes};
    {
        VkBufferCopy tiny{0, 0, 4};
        vkResetCommandBuffer(cb, 0);
        VkCommandBufferBeginInfo bi{VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO};
        vkBeginCommandBuffer(cb, &bi); vkCmdCopyBuffer(cb, imported, devBuf, 1, &tiny); vkEndCommandBuffer(cb);
        collect("recorded, not submitted");
        VkSubmitInfo si{VK_STRUCTURE_TYPE_SUBMIT_INFO}; si.commandBufferCount = 1; si.pCommandBuffers = &cb;
        vkQueueSubmit(queue, 1, &si, VK_NULL_HANDLE);
        collect("right after vkQueueSubmit");
        vkQueueWaitIdle(queue);
        collect("after the 4-byte read completed");
    }
    submit([&] { vkCmdCopyBuffer(cb, imported, devBuf, 1, &region); });
    collect("after GPU read (copy out)");
    for (int k = 2; k <= 4; ++k) { submit([&] { vkCmdCopyBuffer(cb, imported, devBuf, 1, &region); }); char name[40]; std::snprintf(name, sizeof(name), "after GPU read #%d", k); collect(name); }
    submit([&] { vkCmdFillBuffer(cb, imported, 0, bytes, 0x07070707u); });
    const auto gpuWrites = collect("after GPU write (fill)");
    std::printf("GPU fill visible to the CPU: %s\n", base[page] == 7 && base[bytes - 1] == 7 ? "yes" : "NO");
    collect("idle (nothing written)");
    base[0] = 2;
    base[3 * page + 5] = 2;
    collect("after CPU stores (2 pages)");
    submit([&] { vkCmdCopyBuffer(cb, imported, devBuf, 1, &region); });
    base[5 * page] = 3;
    collect("CPU store after a GPU read");
    submit([&] { vkCmdCopyBuffer(cb, devBuf, imported, 1, &region); });
    collect("after GPU write (copy in)");
    std::printf("summary: gpu-write-seen=%llu\n", gpuWrites);
    vkQueueWaitIdle(queue);
    vkDestroyBuffer(dev, imported, nullptr); vkFreeMemory(dev, importedMemory, nullptr);
    vkDestroyDevice(dev, nullptr);
    VirtualFree(raw, 0, MEM_RELEASE);
    return 0;
}
