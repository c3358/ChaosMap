# ChaosMap
Manual PE image mapping library

**Manual map features**
 - x86 and x64 image support
 - Section mapping with proper memory protection flags
 - Image relocations (only 2 types supported. I haven't seen a single PE image with some other relocation types)
 - Imports and Delayed imports are resolved
 - Bound import is resolved as a side effect
 - Module exports
 - Loading of forwarded export images
 - Activation context support
 - Dll path resolving similar to native load order
 - Adding module to some native loader structures(for basic module api support: GetModuleHandle, GetProcAdress, etc.)
 - Image unloading 
