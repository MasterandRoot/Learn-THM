### codewars
- if 的条件判断语句
```python
# 方式一
if  a>b:
    c  =  a
else :    
    c  =  b
# 方式二
c = a if a>b else b
```
- list 列表操作
``` python
arr = [1,2,2,2,2,3]
arr.count(2)  # 结果为4，不用for循环遍历
sum(arr,0) # 求和
```

- 字符串操作
```python
# join()方法用于将序列中的元素以指定的字符连接生成一个新的字符串
s1 = "-"
s2 = ""
seq = ("r", "u", "n", "o", "o", "b") # 字符串序列
print (s1.join( seq ))  # r-u-n-o-o-b
print (s2.join( seq ))  # runoob
# 常用操作
pairs = {'A':'T','T':'A','C':'G','G':'C'}
def DNA_strand(dna):
    return ''.join([pairs[x] for x in dna])
# 字符串分割成列表 split()方法
# 字符串反转[::-1]
return " ".join(x[::-1] for x in (text.split(" ")))

# 字符串映射
# maketrans()方法两个字符串的长度必须相同，为一一对应的关系。
# translate()根据上述方法产生的对应关系翻译字符串
def DNA_strand(dna):
    return dna.translate(str.maketrans("ATCG","TAGC"))  # python 3.4+

# set()方法
a = "nooooobb"
set(a) # ['n','o','b']  去重，生成序列list

# sorted()方法
# sorted(iterable, /, *, key=None, reverse=False)
sorted(a) #['b','n','o']  排序
# 可对字符串直接操作
return int("".join(sorted(str(num), reverse=True)))
# 关于 key参数 示例
x = 'what time are we climbing up the volcano'
lst = x.split(" ")
lstmax = []
num = 0
for i in lst :
    for j in i:
        num = num + ord(j) - 96
    lstmax.append(num)
    num = 0
lst[lstmax.index(sorted(lstmax,reverse=True)[0])]
# 上代码段可精简如下，体会key的用法
max(x.split(), key=lambda k: sum(ord(c) - 96 for c in k))


# map()方法
map(function, iterable, ...)
# function 函数
# iterable 一个或多个序列
def square(x) :         # 计算平方数
    return x ** 2
map(square, [1,2,3,4,5])    # 计算列表各个元素的平方
# <map object at 0x100d3d550>      返回迭代器
list(map(square, [1,2,3,4,5]))   # 使用 list() 转换为列表
[1, 4, 9, 16, 25]

# 格式化 format()
sum = 2.35684
"{:.2f}".format(sum)
# python 3.6 添加f-string,字面量格式化字符串，是新的格式化字符串的语法
# 格式化字符串以 f 开头，后面跟着字符串，字符串中的表达式用大括号 {} 包起来，它会将变量或表达式计算后的值替换进去
name = 'Runoob'
f'Hello {name}'  # 替换变量 'Hello Runoob'
f'{1+2}'         # 使用表达式  '3'

```