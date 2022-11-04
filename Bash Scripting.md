# Bash脚本
### 第一个Bash脚本
- bash开头是以下代码
```bash
#!/bin/bash
```
- 第一个示例
  - 运行前使用`chmod +x example.sh`添加运行权限
```bash
#!/bin/bash
echo "hello world!"
```
### 变量
```bash
#!/bin/bash
name = "Alice"
age = 18
echo "$name is $age years old.
```
### 参数
  - 获取参数 `$n`
  ```bash
  #!/bin/bash
  name=$1
  echo "your name is $name"
  ```
  - 获得参数数量 `$#`
  - 获得当前脚本文件的文件名 `$0`
### 数组
```bash
#!/bin/bash
transport=('car' 'train' 'bike' 'bus')
echo "${transport[@]}"
echo "${transport[1]}"
```
### if语句
```bash
#!/bin/bash
#!/bin/bash
filename=$1
if [ -f $fielname ] &&[ -w $filename ]
then
echo "hello" >> $filename
else
touch $filename
echo "hello touch" >> $filename
fi
```
### 算数运算
- `((...))` 可以进行整数的算术运算
```bash
#!/bin/bash
base=$1
factor=$2
(( base % factor )) && echo "false" || echo "true"
```
- 注意到，如果算术结果为0，命令就算执行失败。
- `&&` 前一句结果执行成功，下一句才会执行
- `||` 前一句执行失败，才会执行



