# app-rtos-benchmark

## 简介

app-rtos-benchmark是一个实时操作系统性能测试框架，包含Rhealstone metric和timer抗干扰性等实时性指标。除Tenon自身的实时性测试外，还支持RT-Thread、Zephyr等主流RTOS。
本仓库的实现参考了https://github.com/RiceChen0/r-rhealstone 和 https://github.com/javamonn/rtems-rhealstone

## 功能说明
### 支持的性能指标
app-rtos-benchmark当前支持的指标如下，测试完成后输出每种指标的N轮测试平均值

- 同优先级线程切换：
两个独立且处于活跃状态的同等优先级线程之间切换所需的cpu周期数量。

- 高优先级线程抢占：
更高优先级任务从正在运行的较低优先级任务处夺取系统控制权所需的cpu周期数量。

- 信号量调度效率：
线程释放信号量和另一个因等待信号量而阻塞的线程的成功获取信号量的cpu周期数量。

- 中断时延：
CPU接收到中断请求与中断服务例程中第一条指令执行之间的cpu周期数量。

- 定时器抗干扰性：
定时器定时的过程中交替打开与关闭中断，实际定时与设置定时的误差count值。

### 统计数据来源

- cpu周期数量：使用ARM架构下的PMU寄存器，读取PMCCNTR_EL0寄存器获取到的cpu周期数量
- count值：读取generic timer的cntvct_el0获取当前count值，测量时间间隔（该数值每秒增长的数值即为设备主频）。

### 配置参数
- 测试轮次
	- RST_BENCHMARKS_COUNT：各个测试指标输出的测试结果均为N轮测试的平均值，修改该值可配置测试轮次(文件路径：include/rst_cfg.h)
- 定时器中断干扰(文件路径：src/rst_set_timer_offset.c)
	- timer_tick：设置每次测试轮次定时的tick数
	配置中断交替打开与关闭的tick数：
	- mask_irq_tick：中断屏蔽的tick数
	- enable_irq_tick：开启中断的tick数

### 运行结果示例
```
 __          __  _                            _       _______                      ____   _____
 \ \        / / | |                          | |     |__   __|                    / __ \ / ____|
  \ \  /\  / /__| | ___ ___  _ __ ___   ___  | |_ ___   | | ___ _ __   ___  _ __ | |  | | (___
   \ \/  \/ / _ \ |/ __/ _ \| '_ ` _ \ / _ \ | __/ _ \  | |/ _ \ '_ \ / _ \| '_ \| |  | |\___ \
    \  /\  /  __/ | (_| (_) | | | | | |  __/ | || (_) | | |  __/ | | | (_) | | | | |__| |____) |
     \/  \/ \___|_|\___\___/|_| |_| |_|\___|  \__\___/  |_|\___|_| |_|\___/|_| |_|\____/|_____/
                                                              Powered by TenonOS (0.1.0~b1a5bf6)


Rhealstone Benchmark Start
RST: task switch benchmark
R-Rhealstone: average task switch time, in cpu cycles - 166 cycle
RST: 50 task switch benchmark
R-Rhealstone: average task switch time, in cpu cycles - 596 cycle
RST: task preempt benchmark
R-Rhealstone: average task preempt time, in cpu cycles - 420 cycle
RST: semaphore shuffle benchmark
R-Rhealstone: average senaphore shuffle time, in cpu cycles - 983 cycle
RST: interrupt latency benchmark
R-Rhealstone: interrupt latency time, in cpu cycles - 1937 cycle
RST: timer deviation under interrupt interference
R-Rhealstone: timer deviation under interrupt interference, in count of generic timer - 7 count
```

## 如何使用

### 操作系统选择

app-rtos-benchmark当前支持Tenon、Zephyr、RT-Thread三种操作系统，可通过include/rst_cfg.h文件修改。配置示例如下

```
#define RST_USING_RTTHREAD 0
#define RST_USING_TENONOS 1	/* 选择Tenon作为被测试的操作系统 */
#define RST_USING_ZEPHYR 0
```

### 测试Tenon
当前支持Tenon rk3568平台的实时性指标测试
#### 构建方式
提供了构建与打包的能力,请使用该仓库构建与打包Tenon镜像 [BoardSupportPackage][tenon-board-support-package]。请使用'defconfigs/ok3568-arm64'配置文件，配置Tenon。
- 搭建Tenon工作目录
```bash
git clone https://gitee.com/tenonos/board-support-package.git
cd board-support-package
bash ./build.sh --init-libs=version-management/lib_config_Tenon_v0.1.0.json
git clone https://gitee.com/tenonos/app-rtos-benchmark.git ../apps/app-rtos-benchmark
git clone https://gitee.com/tenonos-mirror/lib-tlsf.git ../libs/lib-tlsf
```
- 工作目录如下
```
//存在未展开目录，仅展示关键文件
Tenon_workdir
	├── apps
	│   └── app-rhealstone-benchmark
	├── drivers
	├── libs
	│   └── lib-tlsf
	├── plats
	│   └── plat-rk3568
	├── tenon
	└── board-support-package
		└── build.sh              /*执行构建与打包操作的入口脚本*/
```
- 构建Tenon
```bash
bash ./build.sh --board=ok3568 --app=../apps/app-rhealstone-benchmark --config=../apps/app-rhealstone-benchmark/defconfigs/ok3568-arm64
```
- 烧录
Tenon的ok3568板卡烧录指导请参考[load image to board][tenon-ok3568-burn]


### 测试Zephyr
#### 环境配置
- zephyr环境配置与构建请参考 [Zephyr-Start][zephyr-getting-started-guide]
- 成功配置后拉取本仓库代码
```
git clone https://gitee.com/tenonos/app-rtos-benchmark.git ~/zephyrproject/zephyr/samples/app-rtos-benchmark
```
- 如果成功配置Zephyr，目录结构应如下所示
```
//存在未展开目录，仅展示关键文件
zephyrproject
	├── bootloader
	├── modules
	├── tools
	└── zephyr
		└── samples
			└── app-rtos-benchmark
```
#### 板卡适配
由于zephyr目前支持的rk3568的板卡为Firefly生产的ROC-RK3568-PC RAM大小为4G，飞凌嵌入式生产的OK3568-C-V1.1板卡RAM大小为1G，且串口使用的使用的使用频率也不同，所以需修改zephyr提供的设备树文件，以适配OK3568。
1、修改串口时钟频率 （文件路径：dts/arm64/rockchip/rk3568.dtsi）
```
	uart2: serial@fe660000 {
		compatible = "rockchip,rk3568-uart", "ns16550";
		reg = <0xfe660000 0x10000>;
		interrupts = <GIC_SPI 118 IRQ_TYPE_EDGE IRQ_DEFAULT_PRIORITY>;
		clock-frequency = <24000000>;
		reg-shift = <2>;
		status = "disabled";
	};
```
2、修改RAM大小及串口波特率（文件路径：boards/firefly/roc_rk3568_pc/roc_rk3568_pc.dts）
```
	sram0: memory@20000000 {
		device_type = "memory";
		compatible = "mmio-sram";
		reg = <0x20000000 DT_SIZE_M(800)>;
	};

&uart2 {
	status = "okay";
	current-speed = <115200>;
};
```
#### 构建镜像
```bash
cd ~/zephyrproject/zephyr
source ~/zephyrproject/.venv/bin/activate
west build -b roc_rk3568_pc samples/app-rtos-benchmark
```
即可获取镜像文件（镜像路径：zephyrproject/zephyr/build/zephyr/zephyr.bin）

#### 烧录镜像
推荐使用uboot烧录，使用网线链接板卡与主机，进入uboot交互式命令行
- 下载镜像文件,并启动zephyr
```
tftp 0x20000000 zephyr.bin; go 0x20000000
```

### 测试RT-Thread
#### 环境配置

- 拉取RT-Thread代码
```
git clone -b v5.1.0 https://github.com/RT-Thread/rt-thread.git
```
- RT-Thread配置参考[rt-thread-getting-started-guide][rt-thread-getting-started-guide]
- 配置完成后目录结构如下：
```
rt-thread
	├── AUTHORS
	├── bsp
	├── ChangeLog.md
	├── components
	├── documentation
	├── examples
	├── gcc-arm-10.3-2021.07-x86_64-aarch64-none-elf
	├── include
	├── Jenkinsfile
	├── Kconfig
	├── libcpu
	├── LICENSE
	├── README_de.md
	├── README_es.md
	├── README.md
	├── README_zh.md
	├── src
	└── tools
```
- 目前rt-thread v5.1.0 适配rk3568平台存在无法正常启动的问题，需适配修改

1.bsp/rockchip/rk3568/driver/board.c ： 56行
```
   rt_hw_mmu_map_init(&rt_kernel_space, (void *)0xffffd0000000, 0x10000000, MMUTable, 0);
```
2.bsp/rockchip/rk3568/driver/drv_uart.c ： 310行 修改串口波特率
```
       config.baud_rate = 115200;
```
- 拉取本测试本应用代码
```bash
cd  rt-thread/bsp/rockchip/rk3568/
git clone https://gitee.com/tenonos/app-rtos-benchmark.git
rm -rf applications
```

- 目录结构如下：
```
//存在未展开目录，仅展示关键文件
rt-thread
	└── bsp
	    └── rockchip
		    └── rk3568
			└──  app-rtos-benchmark

```
#### 构建镜像
进入到rt-thread/bsp/rockchip/rk3568目录进行输入：
```
scons
```
即可获取镜像文件（镜像路径：rt-thread/bsp/rockchip/rk3568/rtthread.bin）
#### 烧录镜像
推荐使用uboot烧录，使用网线链接板卡与主机，进入uboot交互式命令行
- 下载镜像文件,并启动rt-thread
```
tftp 0x20000000 rtthread.bin; go 0x20000000
```

[tenon-board-support-package]: https://gitee.com/tenonos/board-support-package
[tenon-ok3568-burn]: https://gitee.com/tenonos/documents/blob/master/board_support/ok3568
[TenonOS-Mirror-lib-tlsf]: https://gitee.com/tenonos-mirror/lib-tlsf
[zephyr-getting-started-guide]: https://docs.zephyrproject.org/latest/develop/getting_started/index.html
[rt-thread-getting-started-guide]: https://github.com/RT-Thread/rt-thread/blob/master/bsp/rockchip/rk3568/README_zh.md
