# Bash脚本
### 第一个Bash脚本
- bash开头是以下代码
```bash
#!/bin/bash
```
- 第一个示例
  - 运行前使用`chmod +x example.sh`添加运行权限
  - 可以执行普通的Linux命令
  - 使用 `./example.sh` 运行文件
```bash
#!/bin/bash
echo "hello world!"

whoami

id
```
### 变量
- **不能在变量名称、“ = ”和值之间留有空格！**
```bash
#!/bin/bash
# 错误示范
name = "Alice"
# 正确示范
name="Alice"
age=18
echo "$name is $age years old.
```
### 参数
  - 获取参数 `$n` (n是自然数，表示接收第几个参数，$1 $2 $3 ······)
  ```bash
  #!/bin/bash
  name=$1
  echo "your name is $name"
  ```
  - 执行 `./example.sh Alice`
  - 输出 `your name is Alice`
  - 获得参数数量 `$#`
  - 获得当前脚本文件的文件名 `$0`
  - 用户输入使用 `read`
  ```bash
  #!/bin/bash
  read name
  echo "your name is $name"
  ```
### 数组
```bash
#!/bin/bash
transport=('car' 'train' 'bike' 'bus')
echo "${transport[@]}" #回显所有元素
echo "${transport[1]}" #回显单个元素
#替换元素
transport[1]='trainride'
#删除元素
unset transport[1]
```
### if语句
```bash
#!/bin/bash
filename=$1
# -f 判断文件是否存在
# -w 判断文件是否具有写权限
# -r 判断文件是否具有读权限
# -d 判断是否是目录
if [ -f $fielname ] && [ -w $filename ]
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



