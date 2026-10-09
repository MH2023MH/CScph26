using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;

namespace SecurityAgent.Worker;

/// <summary>
/// Límites de recursos del propio servicio (comparte servidor con 6 apps). Mejor esfuerzo: un fallo se registra y el agente sigue.
/// Prioridad baja en cualquier SO; tope duro de memoria y CPU mediante un Job Object (solo Windows).
/// </summary>
public static class ResourceGovernor
{
    /// <returns>null si los límites quedaron aplicados (o no hacía falta); si no, el motivo del fallo.</returns>
    public static string? Apply(ResourceLimitsOptions o, ILogger log)
    {
        if (!o.Enabled) return null;
        string? error = null;
        try
        {
            if (o.LowPriority) Process.GetCurrentProcess().PriorityClass = ProcessPriorityClass.BelowNormal;
        }
        catch (Exception e) { log.LogWarning(e, "No se pudo bajar la prioridad del proceso"); error = "prioridad: " + e.Message; }

        if (!OperatingSystem.IsWindows()) return error;
        try
        {
            WindowsJobObject.Apply(o.MaxMemoryMb, o.MaxCpuPercent);
            log.LogInformation("Límites aplicados: memoria {Mem} MB, CPU {Cpu}%", o.MaxMemoryMb, o.MaxCpuPercent);
        }
        catch (Exception e) { log.LogWarning(e, "No se pudieron aplicar los límites con Job Object"); error = "job object: " + e.Message; }
        return error;
    }
}

[SupportedOSPlatform("windows")]
internal static class WindowsJobObject
{
    private const int JobObjectExtendedLimitInformation = 9;
    private const int JobObjectCpuRateControlInformation = 15;
    private const uint JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100;
    private const uint JOB_OBJECT_CPU_RATE_CONTROL_ENABLE = 0x1;
    private const uint JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP = 0x4;

    [StructLayout(LayoutKind.Sequential)]
    private struct BasicLimit
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount;
        public ulong ReadTransferCount, WriteTransferCount, OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ExtendedLimit
    {
        public BasicLimit Basic;
        public IoCounters Io;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CpuRate
    {
        public uint ControlFlags;
        public uint CpuRateValue;     // en centésimas de por ciento (1..10000)
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateJobObject(IntPtr attributes, string? name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(IntPtr job, int infoClass, IntPtr info, uint length);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

    public static void Apply(int maxMemoryMb, int maxCpuPercent)
    {
        var job = CreateJobObject(IntPtr.Zero, null);
        if (job == IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());

        if (maxMemoryMb > 0)
        {
            var info = new ExtendedLimit { ProcessMemoryLimit = (UIntPtr)((ulong)maxMemoryMb * 1024 * 1024) };
            info.Basic.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY;
            Set(job, JobObjectExtendedLimitInformation, info);
        }
        if (maxCpuPercent is > 0 and <= 100)
        {
            var cpu = new CpuRate { ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP, CpuRateValue = (uint)(maxCpuPercent * 100) };
            Set(job, JobObjectCpuRateControlInformation, cpu);
        }
        if (!AssignProcessToJobObject(job, Process.GetCurrentProcess().Handle))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        // El handle del job se mantiene abierto a propósito durante toda la vida del proceso.
    }

    private static void Set<T>(IntPtr job, int infoClass, T value) where T : struct
    {
        var size = Marshal.SizeOf<T>();
        var ptr = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(value, ptr, false);
            if (!SetInformationJobObject(job, infoClass, ptr, (uint)size))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        }
        finally { Marshal.FreeHGlobal(ptr); }
    }
}
