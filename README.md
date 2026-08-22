# Operation Triple Barrel

Red team workshop for adversary simulation and/or emulation, in South Korea. Based on [Operation Double Barrel](https://asec.ahnlab.com/ko/94695/)

Covers scenario design, maldev, C2 enhancement, operations, and reporting.

Every project created for Operation Triple Barrel was vibe-coded in two days. So yeah, do NOT use in production. Educational purposes only. 

## Structure

- `barrel-kit/` - UDRL for Adaptix C2. Two-stage PIC+PICO reflective loader built with Crystal Palace.
- `barrel-giga/` - Barrel Pipeline: shellcode loader builder (Barrel Kit + Adaptix agent DLL)
- `barrel-shot/` - RDP/SSH tunneling tool (Go)
- `financial-security-software-I/` - Intentionally vulnerable FSS for initial access
- `operation` - Post-Ex BOFs and operation specific config files 
- `yara` - Yara rules for various Operation Triple Barrel related tools, for responsible disclosure 

## Disclaimer 

This project is provided for educational purposes, authorized security research, and adversary simulation training. All source code and YARA detection rules are published together to promote defensive security awareness and responsible disclosure.

The author assumes no responsibility for any misuse, damage, or illegal activity caused by the use of this project. Users are solely responsible for ensuring compliance with all applicable laws and regulations in their jurisdiction.

---

본 프로젝트는 교육 목적, 허가된 보안 연구, 그리고 공격자 시뮬레이션 교육 목적으로 제공됩니다. 모든 소스 코드와 YARA 탐지 룰은 방어적 보안 인식 향상과 Responsible Disclosure를 위해 함께 배포됩니다.

작성자는 본 프로젝트의 사용으로 인해 발생하는 어떠한 오용, 피해, 또는 불법 행위에 대해서도 책임을 지지 않습니다. 사용자는 자신의 관할권에서 적용되는 모든 법률 및 규정을 준수할 책임이 있습니다.


## Reference

- `./reference/operation-double-barrel.pdf`