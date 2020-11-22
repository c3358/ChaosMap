# ChaosMap
Manual PE image mapping library

**Manual map features**
 - x86 and x64 image support
 - Mapping into any arbitrary unprotected process
 - Section mapping with proper memory protection flags
 - Image relocations (only 2 types supported. I haven't seen a single PE image with some other relocation types)
 - Imports and Delayed imports are resolved
 - Bound import is resolved as a side effect, I think
 - Module exports
 - Loading of forwarded export images
 - Api schema name redirection
 - SxS redirection and isolation
 - Activation context support
 - Dll path resolving similar to native load order
 - TLS callbacks. Only for one thread and only with PROCESS_ATTACH/PROCESS_DETACH reasons.
 - Static TLS
 - Exception handling support (SEH and C++)
 - Adding module to some native loader structures(for basic module api support: GetModuleHandle, GetProcAdress, etc.)
 - Security cookie initialization
 - C++/CLI images are supported
 - Image unloading 
 - Increase reference counter for import libraries in case of manual import mapping
 - Cyclic dependencies are handled properly
