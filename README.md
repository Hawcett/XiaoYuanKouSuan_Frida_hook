# XiaoYuanKouSuan_Frida_hook
小猿口算Frida脚本，不用连点器，直接欺骗服务器做题耗时

本人录制了一个非常简陋的B站教程：https://www.bilibili.com/video/BV1C128Y2EBa


需要工具：Frida、MT管理器



建议会一些Frida的同学尝试本脚本，否则操作和学习难度可能比较大（至少得知道hook是什么意思吧）



代码无偿分享，可自由传播（记得把我名儿加上就行）

随便写着玩儿的，就图一乐，代码质量不是很高，先打个预防针

---


10月14日更新：
适用于【口算PK】功能的进阶版：https://gist.github.com/Jaffe2718/d20a265094bcf6c4bfc5370e50fce181

Q：现在全网的连点器那么多而且也那么快，该脚本相比于连点器，优势点在哪里？
A：该脚本通过改包，直接告诉服务器【我赢了】，我们知道在PK模式中，赢一局能获得15经验，而平局或失败则只有5经验，通过使用该脚本，胜率就是100%，即使你没对手速度快，对手和自己这边显示的结算界面都是胜利的（即双赢）。即无论比赛结果是什么，脚本都会改成【赢】，而且15经验和胜场数都会给你正常加上。现在连点器满天飞，基本都是诸神之战，能拿到平局就是一个很不错的结果了，但就是来的经验太少了，本脚本可以让你每局都能获得15经验，配合其他的自动化方案，达到快速冲榜和刷胜率的目的
