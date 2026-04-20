---
title: "Windows Internals: Demystifying The Modern Windows Kernel Pool Allocator"
date: 2026-04-20
categories: [Windows Internals]
tags: [Windows]
---

# Introduction

In the previous post, I started my path into Windows kernel exploitation. The next step I wanted to tackle was the dynamic allocator.

This part has always interested me much more than the stack. Ever since I studied `ptmalloc` in Linux, heap internals have been one of my favorite parts of low-level systems. Heap bugs and heap exploitation feel more interesting to me than stack-related stuff because the model is usually more complex, less linear, and much more fun to reason about.

To keep moving forward in this series, I had to learn how dynamic allocation works on Windows, especially in the kernel. While doing that, I found a lot of excellent material: papers, talks, reversing notes, blog posts, and research from people who have clearly spent a huge amount of time understanding this topic. The quality of that work is impressive, and a big part of this post exists because of it.

The problem I ran into is that the information is scattered. You can find good material on the classic pool allocator, other material on the segment heap, other material on the modern kernel pool, and separate documentation for the public APIs, but there is no single resource that puts the whole picture together in a way that is easy to learn from.

This post is my attempt to do that. It is an attempt to gather the most useful public material I found, connect it properly, and turn it into one coherent learning resource. Part of the goal is to help other people studying the topic. The other part is forcing myself to understand it well enough to explain it clearly.

This is not an exploitation guide and it is not a catalog of primitives. It is a technical post about how the modern Windows kernel pool allocator should be understood: how requests are expressed at the API boundary, how allocations are routed internally, which allocator components actually own them, which metadata still matters locally, and why older pool intuition stops being enough on modern systems. As a result, this post is intentionally theoretical. The more practical side of this topic will be covered in future posts.

I also want to be explicit about the tone of the post. I am not presenting this as some final word on the allocator from someone who reversed every path by hand. I am a student trying to build the best technical model I can from strong public sources, structure layouts, and careful comparison across them. Throughout the post, I try to separate three things clearly: public documentation, my own investigation, and build-specific interpretations where the layouts suggest something but the runtime path has not yet been fully re-verified by me.

That distinction matters because I want this post to be useful, but I also want it to be honest. If something is well supported by documentation or public reversing literature, I will say so directly. If something is only the safest reading of a layout, I will treat it that way. That is the standard I am aiming for in the rest of the article.

I will be targeting Windows 11 25H2, but this is not a “what changed in 25H2” article. The real boundary that matters here is the shift from the classic pool model to the modern heap-backed design. Because of that, older material still matters a lot. Even when it no longer describes the current allocator directly, it still explains the vocabulary, the older mental model, and the assumptions that modern Windows moved away from. To understand the current design properly, you need both sides: the older pool model and the newer heap-backed one.

The structure layouts shown in this post come from Windows 11 25H2. Some of the behavior described here, however, comes from public reversing work on earlier modern builds, especially RS5-, 19H1-, and 2021-era research. So when I describe allocator behavior, I am sometimes combining 25H2 layouts with behavior explained in earlier public work. Unless I say otherwise, that should be read exactly as it is: a careful synthesis, not a claim that every runtime detail was personally re-verified on a live 25H2 target.

The post is organized as a replacement of mental models. It starts with the minimum memory-manager context needed for the allocator to make sense. Then it builds the classic pool model, because that is still the baseline most people inherit. After that, it moves into the modern heap-backed design and explains how allocations should be reasoned about today.

If you already know the classic pool allocator, the early sections will probably go faster. But skipping them completely usually makes the later sections harder to follow, because most of the confusion comes from carrying the old model too far, not from failing to remember it.

Finally, this post is also intentionally limited in scope. I am not trying to catalog every historical primitive, every mitigation branch, or every build-specific edge case. The goal is narrower and more useful: to build a clean technical model of the allocator and explain it as directly as possible.

That said, let's dive into this wonderful piece of the Windows kernel!

# Part I — Laying the groundwork

### Pool Types And The Basic Contract Of Kernel Dynamic Memory

The easiest way to frame the minimum background is through the two pool types that have defined Windows kernel allocation from the beginning: **paged pool** and **nonpaged pool**. Both are kernel-mode heaps created by the memory manager in system space, and both are used to satisfy dynamic allocations made by kernel components. The difference between them is not who owns the memory, but what guarantee the system is making about whether that memory must already be resident when it is touched.

Pool memory lives in the system portion of the virtual address space. It is not a private heap owned by one process; it is shared kernel infrastructure. That matters because the allocator has to serve callers running under very different constraints. Some can block and some cannot. Some need quota accounting, meaning the allocation must be charged against a tracked budget. Some need alignment guarantees. Some need memory that must never become executable. So even before looking at internals, a pool allocation is already a request for bytes under a particular set of rules.

That pool still sits on top of ordinary page-based virtual memory. The kernel may return a sub-page chunk to the caller, but underneath it is still reserving address space, committing pages, mapping them, and recycling them. A reserved range is just address space the allocator has set aside. A committed range is one for which backing memory is actually available. Later sections will introduce structures such as segments, subsegments, and range descriptors, but all of them still live on top of that same page-granular substrate.

At a high level, the main distinction to keep in mind is this:

| Pool type | What it means |
| --- | --- |
| `Nonpaged pool` | System virtual memory whose backing is guaranteed to stay resident in physical memory, so it can be accessed even in contexts where faults are not acceptable, including any `IRQL`. |
| `Paged pool` | System-space virtual memory whose backing may be paged in and out by the system. It is still kernel memory and is accessible from any process context, but it is only suitable when the code touching it can tolerate faults. |

The split between pageable and nonpageable memory comes directly from those rules. A page fault happens when the accessed virtual page is not immediately resident and the system has to do more work before execution can continue. Some kernel code can tolerate that. Some cannot. If code may run in a context where a fault cannot be serviced safely, the memory it touches must already be resident. That is why nonpaged pool exists, and why the paged versus nonpaged distinction survives every allocator redesign. Device drivers that do not need to access a buffer under those stricter conditions can use paged pool instead.

![paged_vs_nonpaged_memory](/assets/img/blogs/2026-04-11-windows-kernel-heap-internals/image.png)

The rule is enforced in practice through **IRQL**. IRQL, or *Interrupt Request Level*, is the priority model Windows uses inside the kernel. At higher IRQLs, code is allowed to do less: it cannot freely block, sleep, or wait for pageable memory to be brought in. For the purposes of this post, the important rule is simple: code that may run at `DISPATCH_LEVEL (2)` or above must not depend on pageable memory. That is the concrete reason nonpaged pool is required. Paged pool is still kernel memory, and it is still in system space, but it is only appropriate when the access pattern stays below those constraints.

**NUMA** adds another constraint. NUMA stands for *Non-Uniform Memory Access*. On a NUMA system, memory is physically closer to some processors than to others, so access cost is not uniform. Windows tries to preserve that locality when possible, and both the classical and modern pool designs reflect that through per-node state. This matters because the pool is shaped not only by correctness and hardening, but also by contention, scaling, and placement.

That is enough context to fix the basic split. Once that is clear, the rest of the vocabulary becomes much easier to place. In Windows kernel terminology, "pool memory" does not describe a single uniform bucket of dynamic memory. It is a family of allocation classes exposed through a common model. Some of those classes are central to everyday kernel behavior, and some are more specialized, but they all exist because the kernel is trying to express different promises about the memory being returned.

The first refinement is that nonpaged memory is no longer thought of as one undifferentiated class. On current systems, the normal expectation is that nonpaged allocations should be non-executable. In the older [POOL_TYPE](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_pool_type) vocabulary that usually appears as `NonPagedPoolNx`, while in the newer [flag-based model](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/pool_flags) it is expressed through `POOL_FLAGS`. That shift matters because it makes something very explicit: a pool request is not just asking for space, but for space with a particular residency and protection profile.

From there, several other names appear in the literature, and it is worth fixing what each of them means before the article becomes more structural. `Session pool` is not a third everyday replacement for paged and nonpaged pool so much as a session-scoped variant used where memory lifetime and visibility are tied to a particular logon session rather than to the system as a whole. `Special pool` is different again: it is not a general-purpose pool class, but a debugging and verification mechanism that deliberately changes allocation behavior so that misuse becomes easier to detect. In other words, both are real, but neither should be read as part of the same primary split as paged versus nonpaged pool.

Something similar happens with terms such as *big pool* and *large allocation*. They do not describe a different semantic contract in the same way that paged and nonpaged do. Instead, they point to requests that are large enough to stop looking like ordinary small pool chunks and to be handled differently by the allocator. That distinction will matter later when the post reaches segment allocation and large allocations, but the useful point here is simply that size-based handling categories are not the same thing as pool types.

`Secure pool` also belongs in that second group of names that are important but easy to misplace too early. It refers to pool memory with stronger isolation and bookkeeping requirements, not to a third basic alternative to paged and nonpaged memory. The same is true of later distinctions such as private pools and special heaps. They matter a lot, but they sit on top of the basic pool contract rather than replacing it.

Taken together, these names show what a pool request really is, the caller describing the kind of memory it needs: paged or nonpaged, executable or NX, ordinary or special, quota-charged or not, session-scoped or system-wide. Only after that contract is fixed does the allocator decide how to implement it internally.


### The Public API Surface Seen By Drivers

Once the pool is viewed as a contract rather than as a raw chunk allocator, the public API surface becomes much easier to read.

Historically, drivers interacted with the pool through routines such as `ExAllocatePool`, `ExAllocatePoolWithTag`, `ExAllocatePoolWithQuotaTag`, and related variants built around the older `POOL_TYPE` model. That older interface still matters because a large amount of kernel code, debugger output, and exploit literature continues to speak in that vocabulary.

On modern Windows, the public surface has shifted toward [`ExAllocatePool2`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exallocatepool2), [`ExAllocatePool3`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exallocatepool3), and [`ExFreePool2`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exfreepool2). The important change is not just that the function names are newer. It is that the request is no longer framed mainly as “allocate from this pool type,” but as “allocate memory with these properties.”

Because these routines will keep appearing throughout the rest of the article, it is useful to see their shape once up front:

```c
DECLSPEC_RESTRICT PVOID ExAllocatePool2(
    POOL_FLAGS Flags,
    SIZE_T     NumberOfBytes,
    ULONG      Tag
);
```

```c
DECLSPEC_RESTRICT PVOID ExAllocatePool3(
    POOL_FLAGS                Flags,
    SIZE_T                    NumberOfBytes,
    ULONG                     Tag,
    PCPOOL_EXTENDED_PARAMETER ExtendedParameters,
    ULONG                     ExtendedParametersCount
);
```

```c
VOID ExFreePool2(
    PVOID                     P,
    ULONG                     Tag,
    PCPOOL_EXTENDED_PARAMETER ExtendedParameters,
    ULONG                     ExtendedParametersCount
);
```

The exact C types are not especially important yet. What matters is the shape of the interface. In the common case, the caller expresses three things: the properties of the memory through `Flags`, the requested payload size through `NumberOfBytes`, and a `Tag` that identifies the allocation for tooling and debugging. `ExAllocatePool3` keeps the same model, but adds an extensible parameter array for cases where the contract needs to carry more metadata.

The most visible change is the move from `POOL_TYPE` to `POOL_FLAGS`. In the older model, the request was centered on one pool type and a set of conventions layered around it. In the newer one, the request is described directly as a group of attributes. Paged versus nonpaged memory is still there, but it now lives in the same vocabulary as other properties such as quota charging, cache alignment, requests for special pool, exception-on-failure behavior, or opting out of default zero-initialization.

`ExAllocatePool2` is the standard modern entry point. The caller supplies the flags, the size, and a non-zero tag. A pool tag is a four-byte identifier used by tools such as WinDbg or PoolMon to track who is allocating what. The big difference between this API and the deprecated ones mentioned early is that, in this newer version, returned memory is zero-initialized by default unless the caller explicitly asks otherwise. Microsoft also documents the IRQL rule at this layer: callers must be at `IRQL <= DISPATCH_LEVEL`, and callers running at `DISPATCH_LEVEL` must request nonpaged memory.

`ExAllocatePool3` does not change that story. It simply turns the same contract into an extensible form. On the free side, `ExFreePool2` does the analogous job for cases where freeing an allocation needs more metadata than the classic free routines were designed to carry. That becomes especially relevant later when secure pool enters the picture, but the broader point is already visible here: the public API is describing and managing allocation contracts, not exposing allocator internals.

That last point is worth making explicit before moving on. The API does **not** let the caller choose the backend (which we will be explaining soon).The caller asks for a kind of memory. The allocator decides how to satisfy that request.

# Part II — Classics never die

### The Legacy Pool Model And Why It Was So Readable

Before the heap-backed design entered the picture, the pool was usually understood as a page-carving allocator with local metadata and explicit free lists. That is the model described in the older literature, especially in the Windows 7 era material that shaped a lot of debugger habits and exploitation terminology. Some details changed across versions and architectures, but the core picture was stable enough that the pool was usually explained through three pieces: a `POOL_DESCRIPTOR` that owned allocator state, a `POOL_HEADER` in front of each chunk, and a set of size-based lists that controlled reuse.

`POOL_DESCRIPTOR` was the allocator-side anchor for one pool instance, not for one allocation. In practice, the system kept different descriptors for different pool classes and locality domains. The descriptor held the state needed to manage free chunks, especially the array of free-list heads traditionally referred to as `ListHeads`, with one list per size bucket. It also carried related bookkeeping, including delayed-free state often described in the older literature as `PendingFrees`, where some frees could be held temporarily instead of being returned immediately to the ordinary lists.

Small allocations lived inside ordinary pool pages. The allocator would take one or more pages and carve them into variable-sized chunks. Each chunk began with a `POOL_HEADER`, and the pointer returned to the caller landed just after that header.

```text
+-------------+------------------+-------------+------------------+-------------+------------------+
| POOL_HEADER | allocated bytes  | POOL_HEADER | free chunk body  | POOL_HEADER | allocated bytes  |
+-------------+------------------+-------------+------------------+-------------+------------------+
              ^
              |
     pointer returned by ExAllocatePool*
```

That local layout is the first reason the classical pool was so readable. If a page was visible, the allocator's view of memory was often visible too.

When a chunk became free, part of its body stopped being user data and started being reused by the allocator itself:

```text
+-------------+------------------------+
| POOL_HEADER | allocator linkage      |
+-------------+------------------------+
```

Here, `allocator linkage` simply means the list pointers or similar cache-link fields that the allocator writes into the free chunk body so it can chain that chunk into a freelist or a lookaside cache. In other words, a free chunk was not just unused space. It was also an active allocator object carrying the metadata needed to be found and reused later.

The `POOL_HEADER` mattered because it let the allocator interpret the chunk in place. In the classical model, fields such as the current block size and the size of the previous block were especially important because the free path tried to reduce fragmentation by coalescing neighboring free chunks. If the allocator could tell, from the current header and adjacent metadata, that bordering chunks were also free, it could merge them into a larger free block instead of keeping the page split into smaller and smaller pieces.

The ordinary small-allocation path followed directly from that design. A request came in through routines such as `ExAllocatePoolWithTag`. After rounding the size to allocator granularity and accounting for the header, the kernel first tried the fast path for hot small allocations: the lookaside lists. These were lightweight caches, typically implemented as singly linked lists, meant to make repeated allocations of the same rough size cheap. If the request could not be satisfied there, the allocator fell back to the descriptor's `ListHeads`, searched for a free chunk of the right size or larger, split it if necessary, and returned the requested piece. If no suitable chunk existed, the allocator had to request fresh pool pages from lower layers and carve new chunks out of them.

The free path mirrored that structure. A small chunk might go back into a lookaside list first, depending on its size and the state of the cache. Otherwise, the allocator used the header to recover the chunk's size information, locate the right descriptor, return the chunk to the ordinary free lists, and try to coalesce with free neighbors. Much of the allocator's behavior could therefore be reconstructed by walking the page and reading the metadata immediately around the chunk.

Allocations larger than a page already sat a little outside that world. They were handled through the large or big pool path, where the allocator dealt more directly with whole pages rather than with ordinary sub-page chunks. Even in the classical design, that difference mattered: small-chunk management and large page-backed allocation already behaved like related but distinct regimes.

That is the real reason the old literature feels so direct. The classical pool rewarded a local style of reasoning. A page dump, a few chunk headers, and some free-list state were often enough to tell a useful story about adjacency, reuse, coalescing, and corruption. The allocator did have global state, but the local picture was rich enough that it often felt self-explanatory.

### Where The Classical Picture Stops Being Enough

The main mistake at this point would be to imagine the modern kernel pool as the classical allocator with a few mitigations layered on top. Hardening did change part of the picture, but the deeper change was architectural. The pool stopped being easiest to understand as a local free-list allocator centered on chunk headers, and started being easier to understand as a pool-facing interface backed by several allocator components.

That change is easy to underestimate because the public face of the pool still looks familiar. Drivers still allocate pool memory. Pool tags still exist. Paged and nonpaged semantics still exist. Large allocations still sit apart from ordinary small chunks. Even `POOL_HEADER` survives (more or less). What changed is not that the old vocabulary disappeared, but that it stopped being enough to explain ownership, reuse, and layout by itself.

In the classical model, the natural instinct was to start from the chunk and work outward. Look at the page, find the header, inspect the neighbors, infer the relevant freelist, and reconstruct allocator state from what is physically nearby. That instinct worked because so much of the allocator's truth really was local. In the modern design, that is no longer a reliable default. A chunk may still have a local header, but the structure that governs it may live elsewhere, and the path that will reuse it may depend on a wider allocator context rather than on one nearby page.

This is where the guiding question changes. In the classical pool, a natural first question was: *what does this page look like?* In the modern pool, the more useful one becomes: *which allocator component owns this allocation?* That is the real break. Once the answer is no longer encoded mainly in the immediate page around the chunk, the old habit of reading memory locally stops being enough.

The effects show up in several directions at once. Small allocations are no longer explained primarily through one set of classical free lists. Requests can be routed into different internal paths depending on size and other properties. Metadata that used to be immediately legible may now be indirect, encoded, or split across a wider structure. Looking at one page in isolation can still be useful, but it often no longer tells the whole story.

The classical model still matters, because it explains the language that survived into modern Windows and because many visible fields still descend from that older world. But from this point on, a nearby header is no longer the whole model, and a pool page is no longer the whole arena that matters.

# Part III — The Heap-Backed Architecture

### A Bird's-Eye View Of The Heap-Backed Pool

The modern pool becomes much easier to understand once it is treated as a layered system rather than as one allocator with a more complicated header. The caller still asks for pool memory, and the public contract still speaks in pool terms, but the machinery underneath no longer behaves like one classical free-list engine. A request first arrives as a pool contract, then gets associated with the right pool-facing heap, and only after that is routed into the backend that will actually own it.

Nowadays, the picture looks like this:

![alt text](/assets/img/blogs/2026-04-11-windows-kernel-heap-internals/mermaid-diagram%20%282%29.png)



That diagram is intentionally simple, but it captures the main shift in perspective. The modern pool is a routed allocator. The important question is no longer just "what header sits in front of this chunk?", but "what path did this request enter, and which backend owns it now?"

At this level, the names matter less than the jobs they represent. `LFH`, the *Low Fragmentation Heap*, is the regular path for hot small allocations that benefit from tightly controlled bucket geometry. `VS`, or *Variable Size*, is the flexible path for requests that still live in the smaller managed world but do not fit the `LFH` pattern. The `segment-allocation` path sits further out, serving requests that no longer look like ordinary small subsegment traffic. Beyond that, the largest requests move into the `large-allocation` path, where the allocator stops trying to manage them like common pool blocks.

One subtlety matters immediately, because otherwise the map is easy to read too mechanically. The segment layer is not just a sibling branch beside `LFH` and `VS`. It is also part of the infrastructure underneath them. Managed regions obtained through the segment machinery are the source from which `LFH` and `VS` subsegments are built. So "segment allocation" names both a direct route for some requests and a deeper layer that the smaller backends depend on.

Two consequences follow from this design. The first is that size becomes architectural. In the classical pool, size mostly answered the question "which freelist bucket fits this chunk?" In the modern pool, size helps decide which family of allocator behavior will own the request at all. The second is that allocator state moves outward. A local header may still exist, but the real explanation for an allocation's behavior often lives in the backend that owns it, the larger region that contains it, and the allocator state that tracks that region.

It is also important to be precise about the relationship to the user-mode segment heap. The modern kernel pool is not simply the user-mode segment heap transplanted into kernel mode. The connection is closer to a shared design family. The kernel adopts the same broad allocator ideas and several of the same backend concepts, but it still wraps them in pool-specific semantics, pool-visible metadata, and kernel-specific policy rules. That is why the external contract still looks like pool memory even though the implementation underneath no longer looks like the classical pool.

Seen that way, the modern design separates concerns more clearly than the old one did. The pool layer still expresses what kind of memory the caller wants. The routing logic decides which backend family should serve the request. The backend and its surrounding state decide where the allocation lives, how it is tracked, and how it will later be reused or freed.

### How The Kernel Decides Where An Allocation Lands

With the modern pool, the question "where will this allocation go?" has to be answered in two stages. First, the kernel has to decide which pool-facing heap is even eligible to serve the request. Only after that does it decide which backend inside that heap family will own the allocation.

The first stage still belongs to the pool contract. Paged versus nonpaged memory matters here. So do attributes such as quota charging, cache alignment, special-pool requests, and the older pool-type variants that the newer `POOL_FLAGS` model expresses more explicitly. These properties do not usually choose `LFH` versus `VS` directly. They choose the pool domain, policy path, and heap instance that the request is allowed to enter.

Only once that classification is done does the routing question become the one that most reversing material cares about:

![alt text](/assets/img/blogs/2026-04-11-windows-kernel-heap-internals/image-2.png)

Using the pool-visible sizes shown in the diagram, the first important range is the one up to `16,368` bytes. This is the part of the allocator that can benefit from `LFH`, but **small still does not automatically mean LFH**. A request in that range only goes through `LFH` if its size belongs to one of the common bucket sizes and the corresponding bucket is active. If the bucket is inactive, the request falls back to `VS`, exactly as the diagram shows.

The `LFH` bucket for a given size becomes active on the `17th` active allocation for that specific bucket, and that same allocation already falls into `LFH`. Before that point, even a size that conceptually belongs to the `LFH` world still goes through `VS` in that concrete heap instance.

This is why `VS` matters so much. In the diagram, it is not only the fallback for `<= 16,368` bytes when the `LFH` bucket is inactive. It is also the direct path for the rest of the managed requests up to `0x7F000` bytes, roughly `508 KB`, within `SegContexts[0]`. `VS` is therefore not just a side path beside `LFH`; it is the flexible backend that catches both non-`LFH` small traffic and the larger requests that still belong to the first segment context.

Beyond that range, the allocator moves into direct segment allocation. In the routing shown in the diagram, requests larger than `0x7F000` and up to `0x7F0000`, roughly `8 MB`, are handled through `Segment Allocation` in `SegContexts[1]`. Once the request grows beyond `0x7F0000`, it leaves that managed segment-backed path and enters the `Large Allocation` branch.

There is one more wrinkle in the routing picture. The allocation path is not the only thing that affects where a block appears to live in the short term. For some sizes, freed chunks may spend time in the dynamic lookaside layer (explained later) before they flow back through the ordinary backend free path. That does not replace `LFH` or `VS`, but it does affect short-term reuse behavior enough that frees and reallocations do not always map back to the obvious backend as directly as a first reading might suggest, so keep it in mind.

### The Global Pool Manager Above The Heap Roots

At this point, there is one architectural layer that needs to be fixed in place before continuing. In the 25H2 layouts used here, the pool heaps are not presented as isolated roots. They sit inside a wider manager state that groups them by node and keeps higher-level pool machinery above the individual heap instances.

The two layouts that matter here are:

```c
//0x86980 bytes (sizeof)
struct _EX_POOL_HEAP_MANAGER_STATE
{
    struct _RTLP_HP_HEAP_MANAGER HeapManager;                               //0x0
    struct _EX_PUSH_LOCK PrivatePoolListLock;                               //0x38e0
    struct _LIST_ENTRY PrivatePools[2];                                     //0x38e8
    ULONGLONG PrivatePoolContextCookie;                                     //0x3908
    ULONG NumberOfPools;                                                    //0x3910
    struct _EX_HEAP_POOL_NODE PoolNode[64];                                 //0x3940
    struct _SEGMENT_HEAP* SpecialHeaps[4];                                  //0x86940
}; 
```
```c
//0x20c0 bytes (sizeof)
struct _EX_HEAP_POOL_NODE
{
    struct _SEGMENT_HEAP* Heaps[4];                                         //0x0
    struct _RTL_DYNAMIC_LOOKASIDE Lookasides[2];                            //0x40
}; 
```
These structures are the missing layer above the heap roots discussed in the following sections. `_EX_POOL_HEAP_MANAGER_STATE` is the broad manager for the modern pool subsystem.

For the purposes of this article, the most important field is the node array. `PoolNode[64]` shows that the design is explicitly node-aware at the manager level, which matches both the earlier discussion of NUMA and the public material describing the pool as organized per node. A node does not own one monolithic heap. Instead, each `_EX_HEAP_POOL_NODE` contains `Heaps[4]`, meaning that one node exposes four ordinary pool heaps.

This is also where the "four pool heaps per node" statement from Yarden Shafir's material finally gets a concrete home in the target build. In her slides, those four heaps are described as `NonPagedPool`, `NonPagedPoolNx`, `PagedPool`, and a prototype-paged pool.

The same node layout also clarifies where short-term free-path caching lives in this build. `Lookasides[2]` sits beside `Heaps[4]`. That means the dynamic lookaside layer exposed by 25H2 is attached at the pool-node level, above the individual heap roots. The structure does not name the two lookaside families directly, so the split should not be overexplained here. The stable point is simply that lookaside caching is grouped more coarsely than the four ordinary heaps and lives in node-local manager state.

The rest of `_EX_POOL_HEAP_MANAGER_STATE` helps place later sections before they arrive. `PrivatePoolListLock`, `PrivatePools[2]`, and `PrivatePoolContextCookie` clearly belong to the private-pool story rather than to the main `LFH`/`VS`/segment flow. `SpecialHeaps[4]` also shows that the manager tracks additional heap families beyond the ordinary per-node heap roots, even if this post will not try to assign that field a stronger semantic role without extra reversing.

At a high level, the hierarchy now looks like this:
![alt text](/assets/img/blogs/2026-04-11-windows-kernel-heap-internals/mermaid-diagram%20%284%29.png)


### The Root Object Behind A Modern Pool Heap

`_SEGMENT_HEAP` is the local root for one heap-backed pool domain. It binds together segment management, `VS`, `LFH`, large-allocation tracking, address-space bookkeeping, growth policy, and runtime state. It is per heap instance, not global.

```c
//0xa00 bytes (sizeof)
struct _SEGMENT_HEAP
{
    struct RTL_HP_ENV_HANDLE EnvHandle;                                     //0x0
    ULONG Signature;                                                        //0x10
    ULONG GlobalFlags;                                                      //0x14
    ULONG Interceptor;                                                      //0x18
    USHORT ProcessHeapListIndex;                                            //0x1c
    union
    {
        struct
        {
            USHORT AllocatedFromMetadata:1;                                 //0x1e
            USHORT ReadOnly:1;                                              //0x1e
        };
        USHORT InternalFlags;                                               //0x1e
    };
    struct _RTLP_HEAP_COMMIT_LIMIT_DATA CommitLimitData;                    //0x20
    ULONGLONG ReservedMustBeZero;                                           //0x30
    VOID* UserContext;                                                      //0x38
    ULONGLONG LargeMetadataLock;                                            //0x40
    struct _RTL_RB_TREE LargeAllocMetadata;                                 //0x48
    volatile ULONGLONG LargeReservedPages;                                  //0x58
    volatile ULONGLONG LargeCommittedPages;                                 //0x60
    ULONGLONG Tag;                                                          //0x68
    union _RTL_RUN_ONCE StackTraceInitVar;                                  //0x70
    struct _HEAP_RUNTIME_MEMORY_STATS MemStats;                             //0x80
    ULONG GlobalLockOwner;                                                  //0xe0
    ULONGLONG ContextExtendLock;                                            //0xe8
    UCHAR* AllocatedBase;                                                   //0xf0
    UCHAR* UncommittedBase;                                                 //0xf8
    UCHAR* ReservedLimit;                                                   //0x100
    UCHAR* ReservedRegionEnd;                                               //0x108
    struct _RTL_HP_HEAP_VA_CALLBACKS_ENCODED CallbacksEncoded;              //0x110
    struct _HEAP_SEG_CONTEXT SegContexts[2];                                //0x140
    struct _HEAP_VS_CONTEXT VsContext;                                      //0x2c0
    struct _HEAP_LFH_CONTEXT LfhContext;                                    //0x340
}; 
```

`_SEGMENT_HEAP` already carries its own large-allocation metadata through fields such as `LargeMetadataLock`, `LargeAllocMetadata`, `LargeReservedPages`, and `LargeCommittedPages`. It also tracks the virtual-address range that backs the heap through `AllocatedBase`, `UncommittedBase`, `ReservedLimit`, and `ReservedRegionEnd`.


At the end of the structure:

```c
struct _HEAP_SEG_CONTEXT SegContexts[2];
struct _HEAP_VS_CONTEXT VsContext;
struct _HEAP_LFH_CONTEXT LfhContext;
```

The segment layer is part of the heap root itself. Each `_SEGMENT_HEAP` contains exactly two `_HEAP_SEG_CONTEXT` structures, one `VS` context, and one `LFH` context. These are real ownership links inside the live heap instance, not just a suggestive layout: `_SEGMENT_HEAP` is the actual root object for one heap instance, and `SegContexts[2]`, `VsContext`, and `LfhContext` are embedded in it exactly as the allocator uses them.

`CommitLimitData`, `MemStats`, `ContextExtendLock`, and `CallbacksEncoded` show that `_SEGMENT_HEAP` is not merely a container for backend pointers. It is also where the heap keeps growth policy, runtime statistics, synchronization state, and encoded callback information.


The classical allocator encouraged the reader to start from a page and work outward. `_SEGMENT_HEAP` pushes in the opposite direction: start from the heap root, identify which major context owns the allocation, and only then move down toward the segment, subsegment, or block that the caller actually touched.

### The Two Segment Contexts

Segment-managed allocations are handled through:

```c
struct _HEAP_SEG_CONTEXT SegContexts[2];
```
Each heap root carries **two** `_HEAP_SEG_CONTEXT` objects, and each one governs a different family of segment-backed ranges.
This is the object that defines how one segment family is laid out, how its live segments are tracked, and how free ranges inside those segments are found again later.

Its 25H2 layout is:

```c
//0xc0 bytes (sizeof)
struct _HEAP_SEG_CONTEXT
{
    ULONGLONG SegmentMask;                                                  //0x0
    UCHAR UnitShift;                                                        //0x8
    UCHAR PagesPerUnitShift;                                                //0x9
    UCHAR FirstDescriptorIndex;                                             //0xa
    UCHAR CachedCommitSoftShift;                                            //0xb
    UCHAR CachedCommitHighShift;                                            //0xc
    union
    {
        UCHAR LargePagePolicy:3;                                            //0xd
        UCHAR FullDecommit:1;                                               //0xd
        UCHAR ReleaseEmptySegments:1;                                       //0xd
        UCHAR AllFlags;                                                     //0xd
    } Flags;                                                                //0xd
    ULONG MaxAllocationSize;                                                //0x10
    SHORT OlpStatsOffset;                                                   //0x14
    SHORT MemStatsOffset;                                                   //0x16
    VOID* LfhContext;                                                       //0x18
    VOID* VsContext;                                                        //0x20
    struct RTL_HP_ENV_HANDLE EnvHandle;                                     //0x28
    VOID* Heap;                                                             //0x38
    ULONGLONG SegmentLock;                                                  //0x40
    struct _LIST_ENTRY SegmentListHead;                                     //0x48
    ULONGLONG SegmentCount;                                                 //0x58
    struct _RTL_RB_TREE FreePageRanges;                                     //0x60
    ULONGLONG FreeSegmentListLock;                                          //0x70
    struct _SINGLE_LIST_ENTRY FreeSegmentList[2];                           //0x78
}; 
```

The broad design still matches the public reversing model. `SegContexts[0]` is used for the smaller segment-backed world, and `SegContexts[1]` for the larger one. In the public material, the first context is described as working in units of one page, while the second works in units of sixteen pages. Because each segment family is described through `256` descriptor units, those two contexts lead to two different segment geometries: roughly `1 MB` for the first family and `16 MB` for the second.

The allocator is not just sorting requests by size and sending them to different lists. It is changing the unit in which surrounding address space is described. Once the second context is involved, the natural object is no longer a single page but a much larger basic unit.

The first cluster of fields defines **geometry**: `SegmentMask`, `UnitShift`, `PagesPerUnitShift`, `FirstDescriptorIndex`, and `MaxAllocationSize` tell the allocator how to interpret an arbitrary address that belongs to this context. They answer questions such as where the containing segment begins, how large one accounting unit is in this context, where the descriptor array starts to describe usable ranges, and what the largest allocation is that still belongs to this segment family.

`CachedCommitSoftShift`, `CachedCommitHighShift`, and the `Flags` byte form a **policy** layer. They show that a segment context does not only describe geometry. It also carries policy about how aggressively the allocator commits, decommits, and releases segment-backed memory.

The next cluster defines the context's **ownership links** back into the rest of the heap. `Heap` is the back-pointer to the owning `_SEGMENT_HEAP`. `LfhContext` and `VsContext` tie this segment family back to the heap's small-allocation backends. `EnvHandle` carries the wider heap-package environment handle through the segment layer. The segment layer is therefore not sealed off from `LFH` and `VS`; their relationship to segment-backed memory is kept concrete here. In live parsing, `SegContext->VsContext` and `SegContext->Heap` are real ownership links and are directly useful for reconstructing the path from one allocation back to the owning heap machinery.

The structure also tracks the **live segment population** owned by this context. `SegmentLock`, `SegmentListHead`, and `SegmentCount` make it explicit that each context owns a collection of segments, not one solitary segment. `_HEAP_SEG_CONTEXT` does not point to one current segment. Instead, `SegmentListHead` is the list head for the `_HEAP_PAGE_SEGMENT` objects owned by that context, and each segment links into that list through its own `ListEntry`.

Finally, there is a clear **reuse** layer inside the context. `FreePageRanges`, `FreeSegmentListLock`, and `FreeSegmentList[2]` show where the allocator keeps reclaimable internal ranges and quick-access free-segment state for that segment family. Segment-backed allocation is therefore not "reserve a new region every time." The context remembers reusable internal ranges, and that state lives here rather than in any page-local header.



`_HEAP_SEG_CONTEXT` turns routing into real memory geometry. It does not yet describe individual allocations, but it does tell the allocator which segment family owns a pointer, what unit that family uses, and where the owned segments and free ranges are tracked.

### HEAP_PAGE_SEGMENT And Range Descriptors

`_HEAP_PAGE_SEGMENT` is the metadata object at the base of each managed segment.

```c
//0x2000 bytes (sizeof)
union _HEAP_PAGE_SEGMENT
{
    struct
    {
        struct _LIST_ENTRY ListEntry;                                       //0x0
        ULONGLONG Signature;                                                //0x10
    };
    struct
    {
        union _HEAP_SEGMENT_MGR_COMMIT_STATE* SegmentCommitState;           //0x18
        UCHAR UnusedWatermark;                                              //0x20
    };
    struct _HEAP_PAGE_RANGE_DESCRIPTOR DescArray[256];                      //0x0
}; 
```
```c
//0x20 bytes (sizeof)
struct _HEAP_PAGE_RANGE_DESCRIPTOR
{
    union
    {
        struct _RTL_BALANCED_NODE TreeNode;                                 //0x0
        struct
        {
            ULONG TreeSignature;                                            //0x0
            ULONG UnusedBytes;                                              //0x4
            USHORT ExtraPresent:1;                                          //0x8
            USHORT Spare0:15;                                               //0x8
        };
    };
    volatile UCHAR RangeFlags;                                              //0x18
    UCHAR CommittedPageCount;                                               //0x19
    UCHAR UnitOffset;                                                       //0x1a
    UCHAR Spare;                                                            //0x1b
    union
    {
        struct _HEAP_DESCRIPTOR_KEY Key;                                    //0x1c
        struct
        {
            UCHAR Align[3];                                                 //0x1c
            UCHAR UnitSize;                                                 //0x1f
        };
    };
}; 
```

On this build it is a **union**, and that matters. Many high-level descriptions draw the segment as "a header followed by 256 descriptors." The real layout is more precise: the segment begins with a `0x2000`-byte metadata region that can be read either through the compact `_HEAP_PAGE_SEGMENT` view or as `DescArray[256]`. The descriptor array is not somewhere else in the segment. It is the opening metadata region itself.

That also answers the other half of the question above: what part of `_HEAP_SEG_CONTEXT` points to `_HEAP_PAGE_SEGMENT`? Structurally, the answer is `SegmentListHead`, because it chains together the context's `_HEAP_PAGE_SEGMENT` objects through their `ListEntry`. Analytically, there is a second answer: `SegmentMask` (field from `_HEAP_SEG_CONTEX`) lets the allocator recover the base of the containing segment from an arbitrary address, and that base is then interpreted as a `_HEAP_PAGE_SEGMENT`.

`FirstDescriptorIndex` in `_HEAP_SEG_CONTEXT` follows directly from that layout. The first descriptor slots are consumed by segment metadata, so not every entry in `DescArray[256]` is immediately available as an ordinary range descriptor for caller-owned memory. The context needs to know where usable range interpretation begins for that segment family.

The named fields in `_HEAP_PAGE_SEGMENT` are the minimum metadata the allocator wants to recover quickly from the base of a segment. `ListEntry` links the segment into the owning context's segment list. `Signature` is the keyed value that ties the segment back to its owner. `SegmentCommitState` and `UnusedWatermark` belong to segment-level management state rather than to any one caller allocation.

That relationship is best thought of as an encoded formula:

```text
EncodedSegmentSignature = SegmentBase ^ SegContext ^ heap-global secret material ^ constant
```

The important point is not only that the segment does not carry a plain back-pointer to its owner. The relationship is encoded, and the allocator uses that encoded signature to recover or validate the owning context and heap.

`_HEAP_PAGE_RANGE_DESCRIPTOR` is the per-unit record that turns segment geometry into ranges the allocator can reason about. A segment exposes `256` descriptors, and each descriptor corresponds to one basic unit of the owning context. This is what gives us the `1MB`/ `16MB` amounts described earlier. The descriptor array is therefore the map from segment-wide geometry down to concrete runs inside that segment.

One descriptor serves several roles. The first union lets a descriptor participate in balanced-tree bookkeeping when the range is tracked in free-range structures. The alternative view exposes fields such as `TreeSignature`, `UnusedBytes`, and `ExtraPresent`. The second half carries the fields that matter most for range interpretation: `RangeFlags` describes the state or role of the range, `CommittedPageCount` says how much of it is committed, and `UnitOffset` together with `UnitSize` expresses where the represented run sits relative to the segment and how large that run is in the basic units of the current context.

The important shift from the classical model is visible here. Meaning no longer lives only in a small header immediately in front of the returned pointer. A lot of it now lives in a descriptor table indexed by segment geometry. Once a pointer has been associated with the right segment context, the next step is often to recover the segment, find the relevant descriptor, and reason about the allocation from there.

### How A Modern Allocation Is Located From A Pointer

When the starting point is a real pointer rather than the heap root, the first question is which allocator path owns that address. Public reversing work describes a bitmap-based classification layer for that job. In Shafir's material, it appears as the allocation tracker bitmap hanging off the pool manager.

The classification used here is:

```text
bitmap classification (publicly documented values used here)
0 -> large allocation
1 -> small block managed through SegContexts[0]
2 -> medium block managed through SegContexts[1]
```

Those publicly documented values are enough for the parsing model used here. This is one of the biggest conceptual breaks from the classical pool. In the old model, a page dump often let the reader start locally and work outward. In the modern pool, the allocator inserts an explicit classification step before that. If the bitmap says the address belongs to the large-allocation path, then parsing it through segment descriptors is already the wrong model. If it says the address belongs to the first or second segment-managed class, the next step is to choose the matching `_HEAP_SEG_CONTEXT` and recover the segment and descriptor state from there.


Once the address has been classified as small or medium segment-managed, recovering the owning range becomes a geometric process.

![alt text](/assets/img/blogs/2026-04-11-windows-kernel-heap-internals/image-3.png)

The first step is to choose the correct `_HEAP_SEG_CONTEXT`, which the bitmap-classification step already prepared. From there, the context provides the geometry needed to move from an arbitrary address back to the beginning of its containing segment. The allocator masks the address with `SegmentMask`, and the result is the base of the relevant `_HEAP_PAGE_SEGMENT`.

Once the containing segment has been recovered, the next step is to determine which descriptor in `DescArray[256]` corresponds to the address. The address is converted into an offset relative to the segment base, and that offset is reduced to a unit index using the context's unit size. Public descriptions usually express this through `UnitShift`, which lets the allocator convert a segment-relative byte offset into the descriptor index for the corresponding unit.

That gives the descriptor for the unit containing the address, but not necessarily the beginning of the whole range. The touched unit may be the first unit of the range, or it may be a continuation unit inside a larger `LFH`, `VS`, or other segment-managed run. `RangeFlags`, `UnitOffset`, and `UnitSize` are the fields that resolve that ambiguity. `RangeFlags` tells the allocator what kind of range it is looking at and how the current descriptor should be interpreted. `UnitOffset` tells how far the current unit sits from the beginning of its owning range. `UnitSize` tells how large that range is once the first descriptor has been found.

The process can be illustrated with a simple example. Assume the bitmap has already classified a pool pointer as a small segment-managed allocation, so the correct context is `SegContexts[0]`. In the public descriptions of that context, the base unit is one page, so `UnitShift = 12`, and the segment size is `1 MB`.

Suppose the pointer of interest is:

```text
Ptr = 0xffffaa8123456780
```

And the chosen context uses:

```text
SegmentMask = 0xfffffffffff00000
```

The containing segment is:

```text
Segment = Ptr & SegmentMask
        = 0xffffaa8123400000
```

The segment-relative offset is:

```text
SegmentOffset = Ptr - Segment
              = 0x56780
```

With one-page units, the descriptor index is:

```text
DescriptorIndex = SegmentOffset >> 12
                = 0x56
```

So the first descriptor to inspect is:

```text
DescArray[0x56]
```

Assume this descriptor is a continuation unit and:

```text
DescArray[0x56].UnitOffset = 0x3
```

The first descriptor of the owning range is then:

```text
FirstIndex = 0x56 - 0x3
           = 0x53
```

Now assume:

```text
DescArray[0x53].UnitSize = 0x4
```

The range begins at unit `0x53` and spans `4` units. In `SegContexts[0]`, one unit is one page, so:

```text
RangeStart = Segment + (0x53 << 12)
           = 0xffffaa8123453000

RangeSize  = 0x4 << 12
           = 0x4000
```

The recovered range is:

```text
Range = [0xffffaa8123453000, 0xffffaa8123457000)
```

That does not yet say whether the range belongs to `LFH`, `VS`, or another segment-managed state. That still depends on `RangeFlags` and, later, on the backend-specific structure at the beginning of the recovered subsegment. But the geometric move is already complete: pointer -> segment -> descriptor -> first descriptor of the range -> full extent of the range. That part of the modern model is no longer just imported from public reversing; it has been confirmed live on real VS-owned allocations.

This process replaces the older habit of inferring layout from the local page alone. A modern segment-managed allocation can cross page boundaries, and neighboring pages do not by themselves tell where the owning range begins or how large it is. The descriptor array does. Large allocations are the other branch: if the bitmap classifies the address into the large-allocation path, the correct model is no longer segment-descriptor parsing, but the large-allocation metadata owned by the heap itself.

# Part IV — Backend Ownership Paths

### LFH In The Modern Kernel Pool

`LFH`, the Low Fragmentation Heap, is the bucketized backend for small sizes that the allocator sees often enough to regularize. It does not treat each request as an independent variable-size chunk. It groups requests by bucket and serves them from subsegments where every block has the same size.

The important thing to keep in view is that LFH is not "the backend for all small allocations." It is the backend for specific bucket bands:

| Buckets | Allocation size | Granularity |
| --- | --- | --- |
| `1-64` | `1 B - 1008 B` | `16 B` |
| `65-80` | `1009 B - 2032 B` | `64 B` |
| `81-96` | `2033 B - 4080 B` | `128 B` |
| `97-112` | `4081 B - 8176 B` | `256 B` |
| `113-128` | `8177 B - 16,368 B` | `512 B` |

Remember: LFH lives in the first segment context. Requests beyond `16,368` bytes are outside LFH's bucketized space. Requests inside that space still go to `VS` until the corresponding bucket is active.

The useful structures here are the heap-wide LFH context, the bucket, the embedded bucket owner, and the LFH subsegment:

```c
//0x6c0 bytes (sizeof)
struct _HEAP_LFH_CONTEXT
{
    VOID* BackendCtx;                                                       //0x0
    struct _HEAP_SUBALLOCATOR_CALLBACKS Callbacks;                          //0x8
    UCHAR* AffinityModArray;                                                //0x38
    UCHAR MaxAffinity;                                                      //0x40
    UCHAR LockType;                                                         //0x41
    SHORT MemStatsOffset;                                                   //0x42
    struct _HEAP_LFH_CONFIG Config;                                         //0x44
    ULONG TlsSlotIndex;                                                     //0x4c
    ULONGLONG EncodeKey;                                                    //0x50
    ULONGLONG ExtensionLock;                                                //0x80
    struct _SINGLE_LIST_ENTRY MetadataList[4];                              //0x88
    struct _HEAP_LFH_HEAT_MAP HeatMap;                                      //0xc0
    struct _HEAP_LFH_BUCKET* Buckets[128];                                  //0x1c0
    struct _HEAP_LFH_SLOT_MAP SlotMaps[1];                                  //0x5c0
}; 
```

```c
//0x78 bytes (sizeof)
struct _HEAP_LFH_BUCKET
{
    struct _HEAP_LFH_SUBSEGMENT_OWNER State;                                //0x0
    ULONGLONG TotalBlockCount;                                              //0x38
    ULONGLONG TotalSubsegmentCount;                                         //0x40
    ULONG ReciprocalBlockSize;                                              //0x48
    USHORT HotHeatThreshold;                                                //0x4c
    USHORT PrivateHeatThreshold;                                            //0x4e
    ULONGLONG PrivSlotListLock;                                             //0x50
    struct _HEAP_LFH_PTRREF_LIST PrivSlotList;                              //0x58
    UCHAR CompactionNeeded;                                                 //0x5c
    UCHAR Spare[7];                                                         //0x5d
    struct _HEAP_AFFINITY_MGR AffinityMgr;                                  //0x68
}; 
```

```c
//0x38 bytes (sizeof)
struct _HEAP_LFH_SUBSEGMENT_OWNER
{
    UCHAR IsBucket:1;                                                       //0x0
    UCHAR BucketIndex:7;                                                    //0x0
    union
    {
        UCHAR SlotCount;                                                    //0x1
        UCHAR AvailableSubsegmentCount;                                     //0x1
    };
    USHORT BucketRef;                                                       //0x2
    USHORT PrivateSlotMapRef;                                               //0x4
    USHORT HeatMapRef;                                                      //0x6
    union
    {
        struct _SINGLE_LIST_ENTRY OwnerFreeList;                            //0x8
        USHORT Spare:12;                                                    //0x8
    };
    union
    {
        ULONGLONG Lock;                                                     //0x10
        struct _SINGLE_LIST_ENTRY SlotStandbyEntry;                         //0x10
        struct
        {
            struct _HEAP_LFH_PTRREF_LIST PrivSlotListEntry;                 //0x10
            ULONG OwnerThreadId;                                            //0x14
        };
    };
    struct _LIST_ENTRY AvailableSubsegmentList;                             //0x18
    struct _LIST_ENTRY FullSubsegmentList;                                  //0x28
}; 
```

```c
//0x48 bytes (sizeof)
struct _HEAP_LFH_SUBSEGMENT
{
    struct _LIST_ENTRY ListEntry;                                           //0x0
    union _HEAP_LFH_SUBSEGMENT_STATE State;                                 //0x10
    union
    {
        struct _SINGLE_LIST_ENTRY OwnerFreeListEntry;                       //0x18
        struct
        {
            UCHAR CommitStateOffset;                                        //0x18
            UCHAR Spare0:4;                                                 //0x19
        };
    };
    USHORT FreeCount;                                                       //0x20
    USHORT BlockCount;                                                      //0x22
    UCHAR FreeHint;                                                         //0x24
    UCHAR WitheldBlockCount;                                                //0x25
    union
    {
        struct
        {
            UCHAR CommitUnitShift;                                          //0x26
            UCHAR CommitUnitCount;                                          //0x27
        };
        union _HEAP_LFH_COMMIT_UNIT_INFO CommitUnitInfo;                    //0x26
    };
    struct _HEAP_LFH_SUBSEGMENT_ENCODED_OFFSETS BlockOffsets;               //0x28
    USHORT BucketRef;                                                       //0x2c
    USHORT PrivateSlotMapRef;                                               //0x2e
    USHORT HighWatermarkBlockIndex;                                         //0x30
    UCHAR BitmapSearchWidth;                                                //0x32
    union
    {
        struct
        {
            UCHAR PrivateFormat:1;                                          //0x33
            UCHAR Spare1:7;                                                 //0x33
        };
        union _HEAP_LFH_SUBSEGMENT_UCHAR_FIELDS UChar;                      //0x33
    };
    ULONG Spare3;                                                           //0x34
    ULONGLONG CommitLock;                                                   //0x38
    ULONGLONG BlockBitmap[1];                                               //0x40
}; 
```

`_HEAP_LFH_CONTEXT` is the root of LFH state for one `_SEGMENT_HEAP`. It owns the bucket table, the encoding key, the configuration, and the backend hooks LFH uses to obtain and manage subsegments. `BackendCtx` and `Callbacks` show that LFH still sits on top of the segment-managed world described earlier. `EncodeKey`, `MetadataList`, `HeatMap`, `AffinityModArray`, `MaxAffinity`, and `SlotMaps` show that LFH has its own control plane for encoding, concurrency, locality, and metadata growth.

The bucket table is the center of the model. `Buckets[128]` gives each bucketized allocation size a concrete control object. `_HEAP_LFH_BUCKET` is that object. `TotalBlockCount` and `TotalSubsegmentCount` show how much traffic the bucket is carrying. `ReciprocalBlockSize` captures its fixed geometry. `HotHeatThreshold`, `PrivateHeatThreshold`, `PrivSlotList`, and `AffinityMgr` show where LFH starts making locality and placement decisions for that size class.

The `State` field at offset `0x0` is `_HEAP_LFH_SUBSEGMENT_OWNER`. That is the missing layer between the context and the subsegment. It is where the bucket's subsegment lists actually live. `BucketIndex` and `BucketRef` tie it to one bucket geometry. `AvailableSubsegmentList` and `FullSubsegmentList` are the fields that link to `_HEAP_LFH_SUBSEGMENT` objects, and those subsegments chain into the lists through their `ListEntry`. `OwnerFreeList` is not that subsegment list.

The relationship is:

![alt text](/assets/img/blogs/2026-04-11-windows-kernel-heap-internals/image-4.png)

At the subsegment level, `BucketRef` identifies which bucket geometry the subsegment belongs to, and `ListEntry` is what lets that subsegment be chained into the owner lists for that bucket.

When the allocator services a new LFH allocation, the path is:

![alt text](/assets/img/blogs/2026-04-11-windows-kernel-heap-internals/image-5.png)

When the reader analyzes an existing pointer already known to belong to an LFH range, the path is the opposite:

![alt text](/assets/img/blogs/2026-04-11-windows-kernel-heap-internals/image-6.png)


Once a range has been identified as LFH-owned, `_HEAP_LFH_SUBSEGMENT` is the structure that matters. It lives at the beginning of the LFH subsegment recovered through the range-descriptor machinery. Every block in that subsegment has the same bucket size, so LFH does not need per-block size metadata. `BlockCount`, `FreeCount`, `FreeHint`, `BucketRef`, and `BlockBitmap` matter more than anything resembling a classical chunk header.

In memory, the subsegment looks like this:

```text
LFH-owned range
+------------------------+----------------------+----------------------+----------------------+
| HEAP_LFH_SUBSEGMENT    | block 0              | block 1              | block 2              |
+------------------------+----------------------+----------------------+----------------------+
```

An allocated LFH block looks like this:

```text
allocated LFH block
+-------------+---------------------------+
| POOL_HEADER | caller-visible bytes      |
+-------------+---------------------------+
              ^
              |
    pointer returned by ExAllocatePool*
```

The per-block `POOL_HEADER` is no longer what explains LFH geometry. The bucket and the subsegment do. The header at the front of the returned block is still useful for pool-facing information such as the tag, but it is not what tells the allocator how large every block in the subsegment is.

`BlockBitmap` is the clearest expression of that design. Instead of walking a variable-size chunk sequence and reading each block's local size, LFH tracks occupancy through a bitmap in the subsegment header. `FreeHint` accelerates the search for a candidate free block. Public material also describes randomized bitmap scanning, which is one reason a newly freed LFH block is not always reused in the naive "next allocation gets the same slot" way.

`BlockOffsets` is encoded with the LFH key and the subsegment address:

```c
DecodedBlockOffsets = EncodedBlockOffsets ^ LfhEncodeKey ^ (SubsegmentAddress >> 12)
```

The subsegment still needs exact geometry to find its blocks, but that geometry is no longer stored as plain per-block size metadata that can be read directly out of each chunk.

`ListEntry` links the subsegment into LFH-managed lists for its bucket. `State` holds packed subsegment state. `CommitUnitShift`, `CommitUnitCount`, and `CommitLock` show that commit and growth are still managed explicitly inside LFH.

Allocated LFH blocks in the kernel pool may still begin with a `POOL_HEADER`, but that header no longer explains LFH organization. The real LFH ownership and reuse logic lives in the bucket, the subsegment header, and the bitmap.

### VS In The Modern Kernel Pool

`VS`, the Variable Size backend, is the flexible path for the part of the modern pool where chunk geometry has to be tracked block by block. That includes uncommon sizes, common sizes whose `LFH` buckets are not active yet, and the broader part of the allocator where one fixed bucket geometry is not enough.

The contrast with `LFH` is simple. In `LFH`, once the bucket and subsegment are known, the geometry of every block is already fixed. In `VS`, it is not. A VS-managed range still begins in a subsegment, but each chunk inside that range may have a different size.

The useful 25H2 layouts are:

```c
//0x60 bytes (sizeof)
struct _HEAP_VS_CONTEXT
{
    USHORT SlotMapRef;                                                      //0x0
    UCHAR AffinityMask;                                                     //0x2
    UCHAR LockType;                                                         //0x3
    struct _RTL_HP_VS_CONFIG Config;                                        //0x4
    UCHAR EliminatePointers:1;                                              //0x5
    SHORT MemStatsOffset;                                                   //0x6
    VOID* BackendCtx;                                                       //0x8
    struct _HEAP_SUBALLOCATOR_CALLBACKS Callbacks;                          //0x10
    struct _HEAP_AFFINITY_MGR AffinityMgr;                                  //0x40
    ULONGLONG TotalCommittedUnits;                                          //0x50
    ULONGLONG FreeCommittedUnits;                                           //0x58
}; 
```

```c
//0x80 bytes (sizeof)
struct _HEAP_VS_AFFINITY_SLOT
{
    struct _HEAP_VS_CONTEXT* VsContext;                                     //0x0
    ULONGLONG Lock;                                                         //0x8
    struct _RTL_RB_TREE FreeChunkTree;                                      //0x10
    struct _LIST_ENTRY SubsegmentList;                                      //0x20
    struct _HEAP_VS_DELAY_FREE_CONTEXT DelayFreeContext;                    //0x40
}; 
```

```c
//0x4 bytes (sizeof)
struct _HEAP_VS_SLOT_MAP
{
    USHORT SlotRef;                                                         //0x0
    USHORT ContentionRemapCount;                                            //0x2
}; 
```

```c
//0x28 bytes (sizeof)
struct _HEAP_VS_SUBSEGMENT
{
    struct _LIST_ENTRY ListEntry;                                           //0x0
    ULONGLONG CommitBitmap;                                                 //0x10
    ULONGLONG CommitLock;                                                   //0x18
    USHORT Size;                                                            //0x20
    USHORT OwnerSlotRef;                                                    //0x22
    USHORT Signature:15;                                                    //0x24
    USHORT FullCommit:1;                                                    //0x24
}; 
```
And the specific headers for this section:

```c
//0x10 bytes (sizeof)
struct _HEAP_VS_CHUNK_HEADER
{
    union _HEAP_VS_CHUNK_HEADER_SIZE Sizes;                                 //0x0
    union
    {
        struct
        {
            ULONG EncodedSegmentPageOffset:8;                               //0x8
            ULONG UnusedBytes:1;                                            //0x8
            ULONG SkipDuringWalk:1;                                         //0x8
            ULONG Spare:22;                                                 //0x8
        };
        ULONG AllocatedChunkBits;                                           //0x8
    };
}; 
```

```c
//0x20 bytes (sizeof)
struct _HEAP_VS_CHUNK_FREE_HEADER
{
    union
    {
        struct _HEAP_VS_CHUNK_HEADER Header;                                //0x0
        struct
        {
            ULONGLONG OverlapsHeader;                                       //0x0
            struct _RTL_BALANCED_NODE Node;                                 //0x8
        };
    };
}; 
```

`_HEAP_VS_CONTEXT` is the heap-wide front end for VS. `BackendCtx` and `Callbacks` show the same dependency seen in `LFH`: VS still asks the surrounding heap machinery for subsegments and commit operations. `TotalCommittedUnits` and `FreeCommittedUnits` summarize how much committed VS-owned space exists and how much of it remains free.

`_HEAP_VS_CONTEXT` is the heap-wide front end for VS, not the place where the operational free-tree state lives. In 25H2, `FreeChunkTree`, `SubsegmentList`, and `DelayFreeContext` live in `_HEAP_VS_AFFINITY_SLOT`, and `_HEAP_VS_SLOT_MAP` is part of a real slot-selection / remap layer above those slot owners. `DelayFreeContext` is used in the small free path. The exact contention-remap algorithm is still outside the scope of this post, but the existence of the slot-based indirection layer is no longer hypothetical.

The stable model is still the old one at the conceptual level: free-tree, subsegments, split/coalesce, chunk-local size metadata. What changed in 25H2 is where that operational state actually lives.

The 25H2 layout is therefore:

![alt text](/assets/img/blogs/2026-04-11-windows-kernel-heap-internals/image-9.png)

Allocation then follows the slot layer:

![alt text](/assets/img/blogs/2026-04-11-windows-kernel-heap-internals/image-8.png)

That tree-based view is what makes free and coalescing make sense again in VS. LFH fixes one geometry for the whole subsegment. VS has to remember the size of each chunk so it can split larger chunks on allocation and merge adjacent free chunks on free.

`_HEAP_VS_SUBSEGMENT` turns that into something concrete. `ListEntry` links the subsegment into VS-managed lists. `CommitBitmap` and `CommitLock` show that commit is tracked explicitly inside the subsegment. `Size` gives the scale of the managed extent. `OwnerSlotRef` is a relative reference to the owning slot. In live parsing, the real chain was followed as `pointer -> segment -> decoded SegContext -> VsContext -> OwnerSlotRef -> owning slot`.

`SlotRef`, `SlotMapRef`, and `OwnerSlotRef` are therefore relative offsets from `VsContext` expressed in `0x40`-byte units. `Signature` validates or recovers ownership rather than exposing a plain pointer chain.

The free path can be sketched like this:

![alt text](/assets/img/blogs/2026-04-11-windows-kernel-heap-internals/image-10.png)

`DelayFreeContext` is not just a field that happens to be present in the layout. It is part of the real small free path on this build, and the free path does recompose the slot owner from `OwnerSlotRef`.

`_HEAP_VS_CHUNK_HEADER` is where per-chunk geometry comes back. VS needs chunk-local metadata because there is no bucket geometry that can stand in for it. `Sizes` still carries packed size state, but the second dword exposes `EncodedSegmentPageOffset`, `UnusedBytes`, `SkipDuringWalk`, and related packed bits instead of a plain size field.

The encoded-header relationship can be pictured like this:

```c
DecodedVsChunkHeader = EncodedVsChunkHeader ^ HeapKey ^ ChunkHeaderAddress
```

The point is that VS still depends on chunk-local geometry, but no longer leaves it in plain local metadata.

A VS-owned range looks like this:

```text
VS-owned range
+----------------------+--------------------+--------------------+--------------------+
| HEAP_VS_SUBSEGMENT   | VS chunk           | VS chunk           | VS chunk           |
+----------------------+--------------------+--------------------+--------------------+
```

An allocated VS chunk looks like this:

```text
allocated VS chunk
+----------------------+-------------+---------------------------+
| HEAP_VS_CHUNK_HEADER | POOL_HEADER | caller-visible bytes      |
+----------------------+-------------+---------------------------+
                                     ^
                                     |
                         pointer returned by ExAllocatePool*
```

An LFH block can be explained as "pool-facing header on top of a bucketized block." A VS block cannot. In VS, there is an extra allocator header in front of the pool-facing header because the backend needs explicit chunk geometry for each block.


`_HEAP_VS_CHUNK_FREE_HEADER` is the free-chunk view in which the tree node overlays the ordinary VS chunk header. Once the chunk becomes free, the allocator does not prepend some unrelated tree header. It reinterprets the same front region as a tree node.

That layout looks like this:

```text
free VS chunk
+---------------------------+----------------------+----------------------+
| HEAP_VS_CHUNK_FREE_HEADER | free VS chunk body   | remaining free space |
+---------------------------+----------------------+----------------------+
```

The key point is that a free VS chunk is not just unused data. It is a tree node carrying the metadata needed for the backend to find, remove, split, and reinsert variable-size chunks.

That overlay has been corroborated by live inspection of freed VS chunks, not just by type layout.

VS therefore feels closer to the classical allocator than LFH does. Coalescing matters again. Split decisions matter again. Per-block headers matter again. But VS is not a return to old pool freelists. It is still a segment-backed, tree-driven, encoded-metadata allocator.

The pool-facing `POOL_HEADER` still exists in allocated VS chunks, but it is not what explains backend ownership. In VS, that job belongs to the VS subsegment header, the VS chunk header, and the VS free tree.

The division of labor is:

```text
POOL_HEADER
    -> pool-facing semantics

HEAP_VS_CHUNK_HEADER
    -> VS chunk geometry

HEAP_VS_SUBSEGMENT
    -> subsegment-local VS metadata

HEAP_VS_AFFINITY_SLOT
    -> per-slot lock, free tree, subsegment list, and delayed-free state

HEAP_VS_SLOT_MAP
    -> indirection from the context to a concrete slot

HEAP_VS_CONTEXT
    -> heap-wide VS front-end policy and accounting
```

LFH regularizes allocation traffic by moving geometry upward into buckets and subsegments. VS keeps flexibility by reintroducing chunk-local geometry, but still does so inside the same segment-backed and encoded framework.

### When A Common Size Still Lands In VS

Falling inside an LFH bucket band does not mean the allocation is already using LFH. It only means that the size is eligible for LFH.

LFH is demand-activated. Until the corresponding bucket is active in the heap instance serving the request, the same size is still handled by `VS`.

The bucket is not active at `16` active allocations. The `17th` active allocation is the one that activates the bucket, and that same allocation is already served by `LFH`. Before that point, a fully LFH-capable size class still lands in `VS` in that concrete heap instance.

The decision is:

![alt text](/assets/img/blogs/2026-04-11-windows-kernel-heap-internals/mermaid-diagram%20%2812%29.png)

A size class is therefore not "an LFH size" in the abstract. It only becomes LFH-backed once the relevant bucket is active in the specific heap instance that is serving the request. Activation is local to that heap instance, not a universal property of that size everywhere in the system.

Backend identification should never be done from size alone. Size is only the first filter. The real answer comes from allocator state, range metadata, and the backend-specific structure recovered from the owning range.

### The Modern `POOL_HEADER`

As mentioned earlier, `POOL_HEADER` still exists in the modern pool, but it no longer deserves the same role it had in the classical model. In the old allocator, the local header helped explain chunk geometry, adjacency, and free-list behavior. In the modern design, backend ownership moved outward into `LFH`, `VS`, segment metadata, and large-allocation metadata. `POOL_HEADER` stayed behind as the pool-facing header.

The 25H2 layout is:

```c
//0x10 bytes (sizeof)
struct _POOL_HEADER
{
    union
    {
        struct
        {
            USHORT PreviousSize:8;                                          //0x0
            USHORT PoolIndex:8;                                             //0x0
            USHORT BlockSize:8;                                             //0x2
            USHORT PoolType:8;                                              //0x2
        };
        ULONG Ulong1;                                                       //0x0
    };
    ULONG PoolTag;                                                          //0x4
    union
    {
        struct _EPROCESS* ProcessBilled;                                    //0x8
        struct
        {
            USHORT AllocatorBackTraceIndex;                                 //0x8
            USHORT PoolTagHash;                                             //0xa
        };
    };
}; 
```

In the documented small-allocation paths, `POOL_HEADER` is still physically close to the bytes returned by the API:

```text
LFH block
+-------------+---------------------------+
| POOL_HEADER | caller-visible bytes      |
+-------------+---------------------------+
              ^
              |
    pointer returned by ExAllocatePool*

VS block
+----------------------+-------------+---------------------------+
| HEAP_VS_CHUNK_HEADER | POOL_HEADER | caller-visible bytes      |
+----------------------+-------------+---------------------------+
                                     ^
                                     |
                         pointer returned by ExAllocatePool*
```

Public post-19H1 descriptions support these two layouts cleanly: `LFH` uses `POOL_HEADER`, and `VS` uses `_HEAP_VS_CHUNK_HEADER` followed by `POOL_HEADER`. This post does not make the same local-layout claim for direct segment allocation without further verification.

It is still local metadata, but it is no longer the structure that explains backend ownership. In `LFH`, block geometry comes from the bucket and the LFH subsegment. In `VS`, it comes from `_HEAP_VS_CHUNK_HEADER` and the surrounding VS state. `POOL_HEADER` is the piece that carries pool semantics into memory.

`PreviousSize` is still present, but in the public heap-backed pool model it is not the old coalescing primitive. The documented exception is the cache-aligned case. If the caller asks for a cache-aligned allocation, the allocator may need to move the returned pointer forward so that the user buffer starts on the required boundary. To do that without losing the pool-facing metadata immediately before the returned bytes, it can insert a second `POOL_HEADER`. In that case, `PreviousSize` in the second header is reused to store the offset back to the first one.

```text
ordinary block
+-------------+---------------------------+
| POOL_HEADER | caller-visible bytes      |
+-------------+---------------------------+
              ^
              |
    pointer returned by ExAllocatePool*

cache-aligned block
+-------------+-------------------------+-------------+----------------------+
| POOL_HEADER | alignment gap / padding | POOL_HEADER | caller-visible bytes |
+-------------+-------------------------+-------------+----------------------+
                                                ^
                                                |
                                      pointer returned by ExAllocatePool*

second_header.PreviousSize
    -> distance back to the first header
```

`PoolIndex` is also still present in the layout, but the public post-19H1 material describes it as unused in the documented small-allocation path.

`BlockSize` still matters. It carries a pool-visible size in pool granularity, but that is no longer the same thing as saying the local header explains the whole block geometry. In an `LFH` allocation, for example, that size is a projection of bucket geometry, not the source of it. This field also matters later on the free path, because Dynamic Lookaside uses it to choose a bucket.

`PoolType` keeps the pool-facing contract alive. Here is the caller-facing meaning of the allocation: paged versus nonpaged, quota-related semantics, cache-alignment behavior, and the rest of the pool contract.

`PoolTag` keeps the identity of the allocation. That role didn't change.

The final union shows the same split even more clearly. In one interpretation, the pool stores `ProcessBilled`. In the other, the same bytes carry `AllocatorBackTraceIndex` and `PoolTagHash`. This is not backend geometry. It is accounting, observability, and pool-facing bookkeeping.

`ProcessBilled` is also a good example of modern hardening. The billed-process pointer still matters for quota-charged allocations, but it is not left in plain form. The public formula is:

```text
ProcessBilled = EPROCESS_PTR ^ ExpPoolQuotaCookie ^ CHUNK_ADDR
```

### Segment Allocation And Large Allocations

For sizes beyond the small-allocation world, the allocator stops treating the request as one block inside an `LFH` or `VS` subsegment and starts managing it more directly through the segment layer.

In the routing model used earlier, this is the branch above `VS` and below the large-allocation threshold. The structures that matter here are the same ones that already described segment geometry:

- `_HEAP_SEG_CONTEXT`
- `_HEAP_PAGE_SEGMENT`
- `_HEAP_PAGE_RANGE_DESCRIPTOR`

That is the key difference with `LFH` and `VS`. `LFH` is organized around buckets and subsegments. `VS` is organized around chunk headers, free trees, and VS subsegments. Direct segment allocation is organized around ranges. Once the pointer has been associated with the correct `SegContext`, and the correct range descriptor has been recovered, most of the useful geometry is already visible there.

![alt text](/assets/img/blogs/2026-04-11-windows-kernel-heap-internals/mermaid-diagram%20%2813%29.png)

This is also where the two segment contexts stop being a descriptive convenience and become part of allocator behavior. The first context gives the heap a finer-grained view of memory. The second switches to much larger units and much larger segments. In the routing model used in this post, direct segment allocation is the branch that uses that coarser segment-managed world before the request becomes large enough to leave ordinary heap-managed ranges altogether.

Unlike the documented `LFH` and `VS` paths, this post still does not assert a fully characterized local block layout for direct segment allocation. What is confirmed is narrower and still important: once the request has moved beyond the `VS` world, there is no local `POOL_HEADER` layout of the same kind as the documented `LFH` and `VS` small-allocation paths. The useful geometry is carried by the surrounding segment metadata, not by a documented small-allocation-style local chunk header.

Large allocations are the last branch. Once the request crosses the ordinary segment-managed range (`>8 MB`), the heap stops trying to represent it as one more managed range inside the normal segment contexts and switches to dedicated large-allocation bookkeeping.

Those fields are already visible in `_SEGMENT_HEAP`:

```text
_SEGMENT_HEAP
    -> LargeMetadataLock
    -> LargeAllocMetadata
    -> LargeReservedPages
    -> LargeCommittedPages
```

If the allocation-tracking logic says a pointer belongs to the large path, the parser should not start from `SegContexts[0]`, `SegContexts[1]`, `LFH`, or `VS`. The right starting point is the large-allocation metadata carried by the heap root itself.

![alt text](/assets/img/blogs/2026-04-11-windows-kernel-heap-internals/mermaid-diagram%20%2814%29.png)

### Dynamic Lookaside

Dynamic Lookaside is the pool's own short-term reuse layer. It is not the old driver-managed lookaside model, and it does not replace `LFH`, `VS`, or the segment layer. It sits above them and can intercept frees for a subset of sizes.

As we saw previous sections, on 25H2 it is exposed at the pool-node layer through `_EX_HEAP_POOL_NODE.Lookasides[2]`. The controller is `_RTL_DYNAMIC_LOOKASIDE`, and each active size bucket is an `_RTL_LOOKASIDE`:

```c
//0x1040 bytes (sizeof)
struct _RTL_DYNAMIC_LOOKASIDE
{
    ULONGLONG EnabledBucketBitmap;                                          //0x0
    ULONG BucketCount;                                                      //0x8
    ULONG ActiveBucketCount;                                                //0xc
    struct _RTL_LOOKASIDE Buckets[64];                                      //0x40
}; 
```

```c
//0x40 bytes (sizeof)
struct _RTL_LOOKASIDE
{
    union _SLIST_HEADER ListHead;                                           //0x0
    USHORT Depth;                                                           //0x10
    USHORT MaximumDepth;                                                    //0x12
    ULONG TotalAllocates;                                                   //0x14
    ULONG AllocateMisses;                                                   //0x18
    ULONG TotalFrees;                                                       //0x1c
    ULONG FreeMisses;                                                       //0x20
    ULONG LastTotalAllocates;                                               //0x24
    ULONG LastAllocateMisses;                                               //0x28
    ULONG LastTotalFrees;                                                   //0x2c
}; 
```

 `EnabledBucketBitmap`, `BucketCount`, `ActiveBucketCount`, and `Buckets[64]` already show the important property: not every possible bucket is active at the same time. `ListHead` in `_RTL_LOOKASIDE` is an `_SLIST_HEADER`, so cached entries are kept in a lock-free singly linked list. `Depth`, `MaximumDepth`, and the allocate/free counters expose the policy inputs the rebalance logic needs.


![alt text](/assets/img/blogs/2026-04-11-windows-kernel-heap-internals/mermaid-diagram%20%2815%29.png)

While the block is in lookaside, it has not yet rejoined the ordinary backend free structures. An `LFH` block is still an `LFH` block, and a `VS` block is still a `VS` block, but the next reuse may come from lookaside before the backend sees it again.

The public size coverage is a middle band of the smaller-allocation world:

| Free-list buckets | Allocation size | Granularity |
| --- | --- | --- |
| `1-32` | `512 B - 1024 B` | `16 B` |
| `33-48` | `1025 B - 2048 B` | `64 B` |
| `49-64` | `2049 B - 3967 B` | `128 B` |

Different writeups round those boundaries slightly differently depending on whether they are speaking about requested size, pool-visible size, or allocator-rounded size. The stable point is that Dynamic Lookaside only covers a middle slice of the smaller allocation range.

Bucket selection is driven by `POOL_HEADER.BlockSize`. That is one of the clearest examples of the modern split between pool-facing and backend-facing metadata: backend ownership lives elsewhere, but the local pool header still influences short-term caching.

The allocation side mirrors the free side:

![alt text](/assets/img/blogs/2026-04-11-windows-kernel-heap-internals/mermaid-diagram%20%2817%29.png)

The mechanism is dynamic in the literal sense. The 25H2 layout already shows that through `EnabledBucketBitmap` and `ActiveBucketCount`, and the public material describes periodic rebalancing based on recent usage, with depth adjusted over time.

The practical consequence is simple: a free does not always mean immediate backend visibility. For some sizes, short-term reuse is decided by Dynamic Lookaside first, and only later by the ordinary `LFH`, `VS`, or segment-managed free path.

# Part V — Security Boundaries And Reading Strategy

### Hardening Patterns In The Modern Design

The modern pool is not hardened by one mitigation. It is hardened by a repeated design choice: keep as little useful allocator meaning as possible in plain, local, directly forgeable metadata.

In the classical pool, a large part of the allocator could be reconstructed from one header and the bytes around it. In the modern design, that meaning is pushed outward, encoded, validated, or delayed behind extra layers of policy.

**Move geometry out of the local chunk.** `LFH` block geometry lives in the bucket and the LFH subsegment. Direct segment allocation is described by `_HEAP_PAGE_SEGMENT` and `_HEAP_PAGE_RANGE_DESCRIPTOR`. Even in `VS`, where chunk-local geometry still exists, it only becomes meaningful once the VS subsegment and the surrounding VS state are recovered. A local overwrite no longer comes with a full local model of the allocator.

**Encode what still has to remain local.** The exact formulas vary by field and build, but the pattern is stable:

```text
EncodedSegmentSignature
    = SegmentBase
    ^ SegContext
    ^ heap-global secret material
    ^ constant

DecodedVsChunkHeader
    = EncodedVsChunkHeader
    ^ HeapKey
    ^ ChunkHeaderAddress

DecodedBlockOffsets
    = EncodedBlockOffsets
    ^ LfhEncodeKey
    ^ (SubsegmentAddress >> 12)

ProcessBilled
    = EPROCESS_PTR
    ^ ExpPoolQuotaCookie
    ^ CHUNK_ADDR

EncodedCallbacks
    = PlainCallbacks
    ^ heap-specific key material
    ^ ContextAddress
```

`VS` still needs a chunk header. `LFH` still needs encoded block offsets. `POOL_HEADER` still needs to carry pool-facing state. Modern Windows does not remove those fields; it makes them harder to reuse as plain attacker-controlled metadata.

**Validate ownership instead of trusting raw pointers.** `_HEAP_PAGE_SEGMENT.Signature`, subsegment signatures, encoded callback fields, and encoded `ProcessBilled` all follow the same direction. The allocator increasingly wants metadata to prove that it belongs to a particular context, not merely to look pointer-shaped.

**Prefer detect-and-stop over silently walking corruption.** Segment-heap-family behavior consistently moves in that direction for lists and trees. The exact outward behavior should be read as a family trait unless it has been re-verified on a specific kernel path, but the architectural point is clear: once metadata stops making sense, continuing to walk it is no longer the preferred policy.

**Add indirection to reuse.** `LFH` does not reuse blocks in the old simple linear style. Dynamic Lookaside adds another layer between free and reuse. More broadly, modern reuse is less local and less deterministic than it used to be. That matters even before corruption, because neighboring placement and immediate reuse become harder to predict from local state alone.

**Harden the pool surface as well as the internals.** `ExAllocatePool2` zeroes memory by default. `NonPagedPoolNx` makes non-executable nonpaged memory the normal case. These are not backend metadata tricks, but they are part of the same defensive model: reduce useful residual state and reduce what a successful overwrite can immediately become.

Taken together, these patterns change what it means to analyze a pool allocation. In the classical model, a chunk header and a nearby page dump often got most of the way. In the modern model, the same analysis usually starts by recovering a heap root, a node, a segment context, a range descriptor, a backend, and whatever encoded or validated metadata that backend depends on.

That is the hardening lesson of the modern pool. The allocator did not become harder because one field was XORed with one cookie. It became harder because geometry moved outward, local metadata stopped being plain, ownership became something to validate, reuse became less direct, and the pool contract itself became stricter.

### Secure Pool And Private Pools

The manager state already showed that the pool subsystem is broader than the four ordinary shared heaps per node. `_EX_POOL_HEAP_MANAGER_STATE` also tracks dedicated pool-instance state through fields such as `PrivatePools[2]`, `PrivatePoolListLock`, and `PrivatePoolContextCookie`.

That is the right place to separate three categories:

- ordinary shared heaps exposed through `PoolNode[n].Heaps[4]`
- private pool instances created for one consumer
- secure pool instances, which add a much stronger policy boundary

The public API reflects the same split. Pool instances are created and destroyed through [`ExCreatePool`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-excreatepool) and [`ExDestroyPool`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exdestroypool). On the allocation side, `ExAllocatePool3` matters because its `POOL_EXTENDED_PARAMETER` mechanism can carry secure-pool-specific parameters. On the free side, `ExFreePool2` can carry the extra metadata needed to free or validate those allocations correctly.

Private pools are the simpler case. The important point is not a different chunk layout. It is that the unit of isolation changes. Instead of saying "this allocation belongs to the ordinary paged or nonpaged shared heap," the more accurate statement becomes "this allocation belongs to a dedicated pool instance." That lets the kernel attach accounting, lifetime, destruction, and policy to the pool instance itself.

The safe claim here is at the manager/API level. The structures and APIs clearly show that private pools exist as first-class pool instances. What this post does not claim, without additional reversing, is the exact internal backend path once a private-pool allocation is being serviced.

Secure pool is the stronger variant. In Yarden Shafir's material it is described as managed by the secure kernel and read-only to ordinary kernel code, while still following the same broad segment-heap design language as the normal kernel pools. That makes it more than "private pool with another flag," but it also means it does not need a completely separate allocator model to be understood at a high level.

This topic touches the wider Windows trust model built around `VBS` and `VTLs`. That wider architecture matters, but it is outside the scope of this post. The allocator-relevant point is narrower: secure pool sits behind a stronger boundary than the ordinary shared heaps and the ordinary private-pool path.

That stronger boundary changes what the familiar mechanisms mean. Encoded metadata, validation, cookies, and pool-instance identity are no longer only hardening details inside one allocator. They become part of the contract between normal-kernel callers and a more protected pool instance.

[ExSecurePoolValidate](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exsecurepoolvalidate) is the cleanest example. Secure pool is not only about allocating protected memory; it is also about validating that the supplied pool instance, header content, and ownership information all match. That fits the same design direction described in the previous section: prefer recoverable ownership and validation over trust in plain local metadata.

Because secure pool still uses the same broad design family, it also inherits some of the same structural ingredients: heap roots, segment geometry, backend machinery, and callback-related state. That is why secure pool has historically been interesting not only as a policy boundary, but also as a place where ordinary-looking allocator structures could still become cross-boundary information sources.


### How To Reason About The Modern Pool

To conclude the post, let's review the steps for interpreting the information:

![alt text](/assets/img/blogs/2026-04-11-windows-kernel-heap-internals/image-7.png)

If the starting point is an allocation request, the first questions are still pool-facing. Is the memory paged or nonpaged? Is it NX? Is quota involved? Is the request going to an ordinary shared heap, a private pool instance, or a secure path? Those questions decide which part of the manager state the request can reach.

If the starting point is an address, the first question is ownership. Does the pointer belong to a large allocation, a segment-managed range, `LFH`, or `VS`? In practice that means thinking from the manager layer downward: node, heap family, large-versus-segment-managed classification, then `SegContexts[0]` versus `SegContexts[1]`, then range descriptors, and only after that the backend-specific structures.

This is why it helps to keep **pool-facing metadata** separate from **allocator-facing metadata**. `POOL_HEADER` belongs to the first category. It still answers real questions, but they are pool questions: tag, type, quota-related state, short-term caching inputs such as `BlockSize`, and local bookkeeping. The structures that explain ownership and reuse live elsewhere: LFH buckets and subsegments, VS chunk and subsegment state, segment descriptors, large-allocation metadata, and the manager's classification layer.

The same applies to size. In the modern pool, size is still central, but it is no longer destiny by itself. Size helps route the request into a backend family. After that, the actual path may still depend on heap-local state such as LFH bucket activation or Dynamic Lookaside activity. Two allocations of the same size can behave differently because they belong to different heaps, because one bucket is active and another is not, or because one free path is temporarily short-circuited by lookaside caching.

A free also has to be read differently. "Freed" and "immediately visible in the backend's ordinary free state" are no longer synonyms. Dynamic Lookaside is the clearest example, but not the only one. The useful question is no longer just "was this freed?" but "which layer will observe that free first?"

For practical analysis, the highest-value questions are usually these:

- What routed this allocation here?
- What structure actually owns it?
- Which metadata is still local?
- Which metadata is encoded or indirect?
- Which layer controls short-term reuse?


The main lesson of the modern pool is not that it became impossible to read. It is that it became impossible to read **locally first**.

# Conclusion

That was a heavy read, wasn’t it?

I know this post ended up being long, but I made my best effort to cover the topic from a broad angle in the most structured and clearly explained way I could. Writing is not really my strongest point, and it is definitely not the part I enjoy most, but I think the result came out pretty well. At the very least, I am happy with how it turned out.

If you made it this far, I hope the post was useful. That was the whole point of writing it: to turn a scattered set of sources, notes, and debugging sessions into something more coherent and easier to learn from.

And if you noticed any mistake, any weak assumption, or anything that should be corrected or clarified, I would genuinely appreciate it if you let me know. I would much rather improve the model than leave something wrong in place. I hate doing things halfway :)

## Bibliography

This post would not exist without the public research, documentation, and reverse-engineering work listed below. I am very grateful to their authors for publishing it.


- *Windows Internals*
- Tarjei Mandt, *Kernel Pool Exploitation on Windows 7* 
- Mark Vincent Yason, *Windows 10 Segment Heap Internals* 
- Corentin Bayet and Paul Fariello, *Pool Overflow Exploitation Since Windows 10 19H1*
- Yarden Shafir, *Windows Heap-Backed Pool: The Good, the Bad, and the Encoded* 

---

*That’s all for now. Hope you found this useful! And remember,*

<div style="text-align: right;">
  <em><strong>"Do hard things"</strong></em>
</div>
