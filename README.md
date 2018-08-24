1. 生成.key文件：
./cpor k
2. 在原文件filename1所在路径生成.t和.tag文件：
./cpor -t filename1
3. 将.t和.tag拷贝到待验证文件filename2所在路径。
4. 执行如下命令验证文件：
./cpor -v filename2
