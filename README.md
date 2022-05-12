# IoT Security 

## 0x01 Paper 

### 1.Cloud Security

#### [Cloud Platform]
- 2016, IEEE S&P, [Security Analysis of Emerging Smart Home Applications](http://iotsecurity.eecs.umich.edu/img/Fernandes_SmartThingsSP16.pdf)
- 2017, IoT S&P, [Smart solution, poor protection: An empirical study of security and privacy issues in developing and deploying smart home devices](https://dl.acm.org/doi/abs/10.1145/3139937.3139948)
- 2019, Usenix Security,[Discovering and Understanding the Security Hazards in the Interactions between IoT Devices, Mobile Apps, and Clouds on Smart Home Platforms](https://www.usenix.org/conference/usenixsecurity19/presentation/zhou)
- 2020, IEEE S&P, [Burglars' iot paradise: Understanding and mitigating security risks of general messaging protocols on iot clouds](https://ieeexplore.ieee.org/abstract/document/9152619)  
- 2021,ACM,[Who's In Control? On Security Risks of Disjointed IoT Device Management Channels](https://dl.acm.org/doi/abs/10.1145/3460120.3484592)
#### [Cross Cloud]
- 2020, Usenix Security,[Shattered Chain of Trust: Understanding Security Risks in Cross-Cloud IoT Access Delegation](https://www.researchgate.net/profile/Bin_Yuan3/publication/342804736_Shattered_Chain_of_Trust_Understanding_Security_Risks_in_Cross-Cloud_IoT_Access_Delegation/links/5f0700de299bf188160e70af/Shattered-Chain-of-Trust-Understanding-Security-Risks-in-Cross-Cloud-IoT-Access-Delegation.pdf)  

### 2.Communication security

- 2022,AsiaCCS,[Missed Opportunities: Measuring the Untapped TLS Support in the Industrial Internet of Things](https://www.comsys.rwth-aachen.de/fileadmin/papers/2022/2022-dahlmanns-asiaccs.pdf)


### 3.Vulnerability Discovery on Device
#### [Fuzzing]
- 2010, IEEE S&P, [Experimental security analysis of a modern automobile.](https://ieeexplore.ieee.org/abstract/document/5504804/)
- 2013, IJINS, [Analysis of HTTP protocol implementation in smart card embedded web server.](https://pdfs.semanticscholar.org/b2e2/3984c8a2ff489e8c129574ed34ea7613ecda.pdf)
- 2014, HPCS, [Analysis of embedded applications by evolutionary fuzzing.](https://ieeexplore.ieee.org/abstract/document/6903734)
- 2015, AINA, [Fuzzing can packets into automobiles.](https://ieeexplore.ieee.org/abstract/document/7098059/)
- 2016, ACM, [ A. Automated dynamic firmware analysis at scale: A case study
on embedded web interfaces](https://dl.acm.org/doi/abs/10.1145/2897845.2897900)
- 2018, NDSS, [IoTFuzzer: Discovering Memory Corruptions in IoT Through App-based Fuzzing](http://web.cse.ohio-state.edu/~lin.3021/file/NDSS18b.pdf)
- 2019, ACM Workshop, [FirmFuzz: Automated IoT Firmware Introspection and Analysis](https://dl.acm.org/doi/abs/10.1145/3338507.3358616)
- 2019, USENIX Security, [FIRM-AFL: high-throughput greybox fuzzing of iot firmware via augmented process emulation](https://www.usenix.org/conference/usenixsecurity19/presentation/zheng)
- 2022, EuroS&P, [Trampoline Over the Air: Breaking in IoT Devices Through MQTT Brokers](https://github.com/ReAbout/Trampoline-Over-the-Air/blob/main/Trampoline%20Over%20the%20Air%20-%20Breaking%20in%20IoT%20Devices%20Through%20MQTT%20Brokers_validated.pdf)
#### [Symbolic Execution]
- 2020, IEEE S&P, [KARONTE: Detecting Insecure Multi-binary Interactions in Embedded Firmware.](https://conand.me/publications/redini-karonte-2020.pdf)
- 2021,USENIX Security, [Sharing More and Checking Less: Leveraging Common Input Keywords to Detect Bugs in Embedded Systems](https://www.usenix.org/conference/usenixsecurity21/presentation/chen-libo)

#### other
- 2021,ACSAC, [argXtract: Deriving IoT Security Configurations via Automated Static Analysis of Stripped ARM Cortex-M Binaries](https://dl.acm.org/doi/pdf/10.1145/3485832.3488007)

## 4.Vulnerability Analysis Framework on Device
#### [Emulation]
- 2014, NDSS, [AVATAR: A Framework to Support Dynamic Security Analysis of Embedded Systems’ Firmwares](https://www.researchgate.net/profile/Jonas_Zaddach/publication/269197057_Avatar_A_Framework_to_Support_Dynamic_Security_Analysis_of_Embedded_Systems'_Firmwares/links/5e0b2725299bf10bc3852355/Avatar-A-Framework-to-Support-Dynamic-Security-Analysis-of-Embedded-Systems-Firmwares.pdf)
- 2014, ACM, [Prospect: peripheral proxying supported embedded code testing.](https://dl.acm.org/doi/abs/10.1145/2590296.2590301)
- 2015, WOOT, [SURROGATES: Enabling Near-Real-Time Dynamic Analyses of Embedded Systems](https://www.usenix.org/conference/woot15/workshop-program/presentation/koscher)
- 2016, NDSS, [Towards Automated Dynamic Analysis for Linux-based Embedded Firmware.](https://www.ndss-symposium.org/wp-content/uploads/2017/09/towards-automated-dynamic-analysis-linux-based-embedded-firmware.pdf)
- 2018, NDSS Workshop, [Avatar 2: A Multi-target Orchestration Platform.](http://s3.eurecom.fr/docs/bar18_muench.pdf)
- 2020, ACSAC ,[FirmAE: Towards Large-Scale Emulation of IoT Firmware for Dynamic Analysis](https://dl.acm.org/doi/abs/10.1145/3427228.3427294)
- 2021, USENIX Security, [Automatic Firmware Emulation through Invalidity-guided Knowledge Inference](https://www.usenix.org/system/files/sec21fall-zhou.pdf)
## 5.Vulnerability Mitigation

#### [Hotpatch]
- 2021, NDSS, [HERA: Hotpatching of Embedded Real-time Applications](https://www.ndss-symposium.org/ndss-paper/hera-hotpatching-of-embedded-real-time-applications/)
- 2022, USENIX Security, [RapidPatch: Firmware Hotpatching for Real-Time Embedded Devices](https://www.usenix.org/system/files/sec22summer_he-yi.pdf)
#### [Sensitive Information] 
- 2016, USENIX Security, [FlowFence: Practical Data Protection for Emerging IoT Application Frameworks](https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_fernandes.pdf)  
- 2018, USENIX Security, [Sensitive Information Tracking in Commodity IoT](https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-celik.pdf)
#### [Authentication and Access Control] 
- 2017, IEEE S&P, [Security Implications of Permission Models in Smart-Home Application Frameworks](https://www.infoq.com/articles/smart-home-permission-models) 
- 2017, NDSS, [ContexIoT: Towards Providing Contextual Integrity to Appified IoT Platforms](https://amir.rahmati.com/dl/ndss17/ContexIoT_NDSS17.pdf) 
- 2017, USENIX Security, [SmartAuth: User-Centered Authorization for the Internet of Things](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-tian.pdf)
- 2017, Access Control Models, [FACT: Functionality-centric Access Control System for IoT Programming Frameworks](http://www.corelab.or.kr/Pubs/sacmat17_fact.pdf)
- 2018, USENIX Security, [Rethinking Access Control and Authentication for the Home Internet of Things (IoT)](https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-he.pdf)
- 2018, IEEE SecDev, [Tyche: Risk-Based Permissions for Smart Home Platforms](https://arxiv.org/pdf/1801.04609)
- 2019, NDSS, [IoTGuard: Dynamic Enforcement of Security and Safety Policy in Commodity IoT](https://cs.uwaterloo.ca/~yaafer/teaching/papers/ndss2019_07A-1_Celik_paper.pdf)
#### [Privacy Inference via Sensors and Defenses]
- 2017, arXiv, [Spying on the Smart Home Privacy Attacks and Defenses on Encrypted IoT Traffic](https://arxiv.org/pdf/1708.05044.pdf) 
- 2017, arXiv, [Detecting Spies in IoT Systems using Cyber-Physical Correlation](https://faculty.washington.edu/lagesse/publications/HiddenSensorDetection.pdf) 
- 2018, arXiv, [Peek-a-Boo: I see your smart home activities even encrypted](https://arxiv.org/pdf/1808.02741)
- 2018, arXiv, [Closing the Blinds: Four Strategies for Protecting Smart Home Privacy from Network Observers](https://arxiv.org/pdf/1705.06809.pdf)
- 2018, arXiv, [A Developer-Friendly Library for Smart Home IoT Privacy Preserving Traffic Obfuscation](https://arxiv.org/pdf/1808.07432.pdf)
- 2022, USENIX Security,[Lumos: Identifying and Localizing Diverse Hidden IoT Devices in an Unfamiliar Environment](https://www.usenix.org/conference/usenixsecurity22/presentation/sharma-rahul)
### 6.IoT Surveys  
- 2017, arXiv, [A Survey of Machine and Deep Learning Methods for Internet of Things (IoT) Security](https://arxiv.org/pdf/1807.11023.pdf)
- 2017, arXiv, [Understanding IoT Security Through the Data Crystal Ball: Where We Are Now and Where We Are Going to Be](https://arxiv.org/pdf/1703.09809.pdf)
- 2017, IEEE S&P Magazine, [Internet of Things Security Research: A Rehash of Old Ideas or New Intellectual Challenges](https://arxiv.org/pdf/1705.08522.pdf)
- 2018, BlackHat, [IoT Malware: Comprehensive Survey, Analysis Framework and Case Studies](https://i.blackhat.com/us-18/Thu-August-9/us-18-Costin-Zaddach-IoT-Malware-Comprehensive-Survey-Analysis-Framework-and-Case-Studies-wp.pdf)
- 2018, arXiv, [A Survey on Sensor-based Threats to Internet-of-Things (IoT) Devices and Applications](https://arxiv.org/pdf/1802.02041.pdf)
- 2018，信息安全学术，[IoT 智能设备安全威胁及防护技术综述](http://jcs.iie.ac.cn/ch/reader/create_pdf.aspx?file_no=20180104&year_id=2018&quarter_id=1&falg=1)    
- 2018, arXiv, [IoT Security: An End-to-End View and Case Study](https://arxiv.org/pdf/1805.05853.pdf)
- 2019, arXiv, [Program Analysis of Commodity IoT Applications for Security and Privacy: Challenges and Opportunities](https://arxiv.org/pdf/1809.06962.pdf)
- 2019, IEEE S&P, [SoK: Security Evaluation of Home-Based IoT Deployments](https://www.computer.org/csdl/proceedings/sp/2019/6660/00/666001a208-abs.html)   
- 2019, USENIX Security,[Looking from the mirror: evaluating IoT device security through mobile companion apps](https://www.usenix.org/conference/usenixsecurity19/presentation/wang-xueqiang)
- 2020, MDPI, [A Survey of Security Vulnerability Analysis, Discovery, Detection, and Mitigation on IoT Devices](https://www.mdpi.com/1999-5903/12/2/27)


## 0x02 Website
- [知道创宇IoT专栏](https://paper.seebug.org/category/IoT/)   
- [UMICH IoT](https://iotsecurity.engin.umich.edu/)
- [IoT Security Wiki](https://iotsecuritywiki.com/)
- [物联网安全百科](https://iot-security.wiki/)
#### Communication Security
- [Researchers exploit ZigBee security flaws that compromise security of smart homes](https://www.csoonline.com/article/2969402/microsoft-subnet/researchers-exploit-zigbee-security-flaws-that-compromise-security-of-smart-homes.html)   
- [KCon 2018 议题解读：智能家居安全——身份劫持](https://paper.seebug.org/690/) 
#### Device Security 
- [智能门锁网络安全分析报告](https://mp.weixin.qq.com/s?__biz=MzUzNDYxOTA1NA==&mid=2247486313&idx=1&sn=adf4560cfceca1e996cbf173e5bb415f&chksm=fa90bda8cde734bebaa34b9b9fc9414907f2f61b80ffa1af70af31a9c56c1590065ac47c972c&mpshare=1&scene=1&srcid=1113NO91YeEE2SnAbvkDRwah#rd)
- [智能家居行业网络安全风险分析报告 ](https://www.secrss.com/articles/3603)
#### App Security
#### Platform Security
## 0x03 Topic of Xiaomi
- [小米IoT开发者平台](https://iot.mi.com/new/guide.html?file=%E9%A6%96%E9%A1%B5) 
#### MIDC
- [MIDC • 2017 小米IoT安全峰会议题 PPT 公布](http://www.vipread.com/library/list/241) 
>list:   
解密人脸解锁   
IoT 固件安全的设计和攻防   
僵尸网络 Hajime 的攻防逻辑   
IoT 被遗忘的攻击面   
特斯拉安全研究：从一次到两次的背后   
小米 IoT 安全之路   
IoT与隐私保护   

- [MIDC • 2018 小米IoT安全峰会议题 PPT 公布](https://paper.seebug.org/761/)   
>list：   
小米 IoT 安全思考与实践   
小米IoT隐私数据合规实践   
IoT + AI + 安全 =？   
IoT 安全战地笔记   
智能门锁，让居住更安全   
IoT Reverse Engineering   
大安全下的 IoT 安全威胁演变与应对 
#### Communication Security
- [绿米网关局域网通信协议V1.1.1](/files/绿米网关局域网通信协议V1.1.1_2017.12.21.doc)   
- [网关局域网通信协议V2.0](https://docs.opencloud.aqara.cn/development/gateway-LAN-communication/)    
- [小米智能家居设备流量分析及脚本控制](https://www.freebuf.com/articles/terminal/181846.html)    
- [小米接入教程](https://homekit.loli.ren/docs/show/12 )       
- [智能家居设备的另一种打开方式——如何控制局域网中的小米设备](https://paper.seebug.org/616/)  
#### Device Security
- [Reverse Engineering 101 of the Xiaomi IoT ecosystem HITCON Community 2018 Dennis Giese](https://hitcon.org/2018/CMT/slide-files/d2_s1_r0.pdf)  
- [如何成功劫持小米Mi扫地机器人](https://www.kaspersky.com.cn/blog/xiaomi-mi-robot-hacked/9107/)  
### Ref:
###### https://github.com/Beerkay/IoTResearch
