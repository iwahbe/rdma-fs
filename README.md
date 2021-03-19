## RDMA Filesystem Over FUSE

### Plan
Building the system will happen in 3 phases. 
1. Build a pass-through file system, which mirrors the main file system.
   - Done
2. Figure out message passing over RDMA. Get the host and the NPU talking to
   each-other.
3. Connect the pass-through file system to the `rdma` server.
   - I think this will involve hacking together a new session type in `fuser`.
