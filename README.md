# attach-mechanism-enabler
This project allows reenabling the JVM attach mechanism if it was disabled at launch with ``-XX:+DisableAttachMechanism``.

It searches for patterns that correspond to the method [AttachListener::init()](https://github.com/openjdk/jdk21u/blob/jdk-21%2B35/src/hotspot/share/services/attachListener.cpp#L453) in jvm.dll using [Zydis](https://github.com/zyantific/zydis), then calls that method.

It has been tested on Windows 11 with Zulu 8, 17, and 21 JREs.

The attach listener will be initialized, but the JVM will still report it as disabled, which means that ``VirtualMachine#attach`` will fail.

As a workaround, [jattach](https://github.com/jattach/jattach) can be used.

---
You can also use the code below to fool ``sun.jvmstat.monitor.MonitoredVmUtil#isAttachable`` and make it always return true:
```java
import sun.jvmstat.monitor.*;
import sun.jvmstat.perfdata.monitor.PerfStringConstantMonitor;
import sun.jvmstat.perfdata.monitor.protocol.local.MonitoredHostProvider;

import java.lang.reflect.Field;

public class PatchedMonitoredHostProvider extends MonitoredHostProvider {
    private static final Field dataField;
    static {
        try {
            dataField = PerfStringConstantMonitor.class.getDeclaredField("data");
            dataField.setAccessible(true);
        } catch (NoSuchFieldException e) {
            throw new RuntimeException(e);
        }
    }

    public static void init() {
        System.setProperty("sun.jvmstat.monitor.MonitoredHost", PatchedMonitoredHostProvider.class.getName());
    }

    public PatchedMonitoredHostProvider(HostIdentifier hostId) {
        super(hostId);
    }

    @Override
    public MonitoredVm getMonitoredVm(VmIdentifier vmIdentifier, int i) throws MonitorException {
        MonitoredVm vm = super.getMonitoredVm(vmIdentifier, i);

        try {
            Monitor monitor = vm.findByName("sun.rt.jvmCapabilities");
            String data = (String) dataField.get(monitor);
            dataField.set(monitor, "1" + data.substring(1));
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        }

        return vm;
    }
}
```

---
Otherwise, you can manually patch that bit with System Informer/Process Hacker:

Look for the target java process, go to Properties -> Handles -> ``\Sessions\*\BaseNamedObjects\hsperfdata_<username>_<pid>``, right click -> Read/Write memory
<img width="888" height="324" alt="image" src="https://github.com/user-attachments/assets/137108fd-643e-4385-b847-75d1c81062db" />

Look for the string ``sun.rt.jvmCapabilities``. There is a null byte after it, and the next byte is the attach mechanism supported bit (should be ``0x30``, or ``0`` as ascii)
<img width="1098" height="840" alt="image" src="https://github.com/user-attachments/assets/c2a4ab37-8ce7-4862-9b52-bf3710adf2cb" />

Replace that byte with ``0x31`` (or ``1`` as ascii), like so:
<img width="1123" height="842" alt="image" src="https://github.com/user-attachments/assets/266cd668-9e41-42a2-a4b5-483ebb17da2b" />
Finally, press Write.
