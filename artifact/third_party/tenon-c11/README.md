<div align="center">
<img src=logo.png width=20% />
</div>
<br />

<div align="center">

[![Static Version Badge](https://img.shields.io/badge/Tenon_Version-v0.2.0-brightgreen)][tenon-latest] [![Static License Badge](https://img.shields.io/badge/License-Apache--2.0-green)][tenon-copyright] ![Static Language Badge](https://img.shields.io/badge/Language-C/C++-red)

</div>

# TenonOS：简化复杂性，释放创新力，重塑操作系统的开发模式

TenonOS是一款基于LibOS架构的操作系统，旨在提升操作系统扩展、裁剪、移植效率，基于丰富的微库组件池，实现跨场景、跨行业、跨领域的快速能力复用，灵活生成与场景最契合的OS实体。

## 架构
<div align="center">
<img src=arch.png />
</div>
<br />

与传统宏内核、微内核架构的操作系统不同，Tenon采用微库解耦架构，借鉴[Unikraft][unikraft-website]的实现方式，将kernel、驱动、服务进一步拆分封装成接口解耦、功能独立的微库，使用Kconfig进行微库配置和依赖关系管理。Tenon不约束操作系统或内核必须由哪些部件组成，用户可以根据自己的需求选择[TenonOS社区][tenon-community]或[UK社区][unikraft-website]提供的微库，甚至可以基于框架提供的API封装实现自己的调度器、内存分配器、线程池、同步锁、特定系统调用等微库，达到任意裁剪、新增、优化操作系统功能的目的，使软硬件性能、资源利用率达到极致。

<div align="center">
<img src=os-instance.png width=70%/>
</div>
<br />

目前Tenon的构建代码和基础框架使用[Unikraft V0.16.0][unikraft-base]版本作为基线，并增加以下平台和主要特性：

### 支持的平台

|平台| CPU架构 | 启动协议 | 状态 |
|---|---------|------------|------|
|[树莓派][plat-raspi]| arm64 |Linux 64-bit boot protocol|已支持|
|[rk3568][plat-rk3568]|arm64|Linux 64-bit boot protocol|已支持|
|[kvm][tenon-plat-kvm]|arm64|Linux 64-bit boot protocol|已支持|
|[d9][tenon-plat-d9]|arm64|Linux 64-bit boot protocol|已支持|

### 关键特性
* [x] 支持嵌入式平台：plat-raspi、plat-rk3568
* [x] posix接口兼容 -- 持续更新
* [x] 调试工具：openocd+gdb
* [x] 调试工具：NS8250串口驱动
* [x] 实时微库：支持抢占式调度
* [x] 实时微库：支持中断抢占、中断嵌套
* [x] 同步微库：支持自旋锁、互斥锁、信号量、消息队列
* [x] 支持虚拟文件系统
* [x] 网络微库：netdev框架
* [ ] SMP：支持多核启动和跨核调度
* [ ] 网络微库：rk3568网卡驱动

### 示例应用
[helloworld][app-helloworld]<br>

[rtos-benchmark][rtos-benchmark]<br>

[对象识别][app-object-detect]<br>

[busybox][app-busybox]

## 如何使用
### 代码结构
除Tenon框架API和核心微库外，[TenonOS社区主仓][tenon-projects]还提供了用于编译构建的[板级支持包][tenon-bsp]仓库、以***app***为前缀的应用仓库、以***lib***为前缀的外部微库、以***driver***为前缀的外部驱动微库、以***plat***为前缀的外部平台仓库。这些微库会在后续逐步开源。构建时工作目录结构如下
```
.
├── apps                   /*此目录用于维护运行在os之上的app，下为示例*/
│   ├── app-busybox
│   ├── app-elfloader
│   ├── app-helloworld
│   ├── app-helloworld-cpp
│   └── app-tflite
├── board-support-package  /*此目录用于维护板级支持包，包括设备树、bootloader等。下为示例*/
│   ├── kvm
│   └── raspberry-pi-3b+
├── drivers                /*此目录用于维护外部驱动，“外部”指不在tenon核心仓维护的代码仓*/
├── libs                   /*此目录用于维护外部微库，下为示例*/
│   ├── lib-libcxx
│   └── lib-tflite-micro
├── plats                  /*此目录用于维护外部平台，包含对应平台的os初始化代码。下为示例*/
│   ├── plat-raspi
│   └── plat-rk3568
└── tenon                  /*tenon核心仓库，用于维护API框架和内部微库*/
    ├── arch               /*cpu架构相关代码*/
    ├── build              /*保存构建出的镜像和中间产物*/
    ├── drivers            /*用于维护内部驱动*/
    ├── include            /*跨微库共用的宏定义、结构体定义等*/
    ├── lib                /*用于维护框架微库和内部微库*/
    ├── plat               /*用于维护内部平台，如kvm*/
    └── support            /*编译构建脚本*/
```
### 使用指导
Tenon使用make完成编译构建，当前支持kvm、树莓派3b+、rk3568等平台，使用指导请参考[quick_start][quick_start]

## 社区贡献

Tenon欢迎各方以个人、组织、企业形式参与到社区贡献当中，贡献指导请参考[Contributing][tenon-contributing]

### License

Tenon采用[Apache-2.0][tenon-copyright]开源许可协议。当前代码仓中仍有部分unikraft代码，unikraft采用[BSD-3-Clause][unikraft-copyright]开源许可协议。当前开发过程中，若要修改uk原有微库的代码，请保留文件中原有LICENSE说明，新增微库或特性请使用[Apache-2.0][tenon-copyright]协议。后续开源进程中我们将逐步移除对uk代码的依赖。

## 参考资源

* [设计文档][tenon-design]
* [API文档][tenon-api]
* [博客][tenon-blog]
* [RequestForComments][tenon-rfcs]
* [微库中心][tenon-libcenter]
* [社区主页][tenon-community-mainpage]
* [Roadmap][tenon-roadmap]



[unikraft-website]: https://unikraft.org
[unikraft-base]: https://github.com/unikraft/unikraft/tree/RELEASE-0.16.0
[unikraft-copyright]: COPYING_uk.md
[tenon-latest]: https://gitee.com/tenonos/tenon/releases/tag/release-v0.2.0
[tenon-community]: https://gitee.com/tenonos
[tenon-projects]: https://gitee.com/organizations/tenonos/projects
[plat-raspi]: https://gitee.com/tenonos/plat-raspi
[plat-rk3568]: https://gitee.com/tenonos/plat-rk3568
[app-object-detect]: https://gitee.com/tenonos/app-object-detection
[app-helloworld]: https://gitee.com/tenonos-mirror/app-helloworld
[app-busybox]: https://gitee.com/tenonos/app-busybox
[quick_start]: https://gitee.com/tenonos/documents/tree/master/howto/quick_start
[tenon-bsp]: https://gitee.com/tenonos/board-support-package
[rtos-benchmark]: https://gitee.com/tenonos/app-rtos-benchmark
[tenon-contributing]: https://gitee.com/tenonos/documents/tree/master/contributor/CONTRIBUTING.md
[tenon-copyright]: COPYING.md
[tenon-design]: https://gitee.com/tenonos/documents/tree/master/design
[tenon-api]: https://gitee.com/tenonos/documents/tree/master/api
[tenon-blog]: https://gitee.com/tenonos/documents/tree/master/blog
[tenon-rfcs]: https://gitee.com/tenonos/request-for-comments/board
[tenon-libcenter]: https://www.tenonos.org.cn/libcenter
[tenon-community-mainpage]: https://www.tenonos.org.cn
[tenon-roadmap]: https://gitee.com/tenonos/roadmap
[tenon-plat-kvm]: https://gitee.com/tenonos/tenon/tree/master/plat/kvm
[tenon-plat-d9]: https://gitee.com/tenonos/plat-d9
