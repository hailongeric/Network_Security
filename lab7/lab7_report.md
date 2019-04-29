## SQL Injection Attack Lab Report

### Task1: Get Familiar with SQL Statements 

database 名称 Users,  contains a table 名称 credential

使用命令示例：

![1544668901309](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1544668901309.png)

打印出Alice的信息：

![1544668924493](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1544668924493.png)

###  Task2: SQL Injection Attack on SELECT Statement 

#### Task 2.1: SQL Injection Attack from webpage. 

由于我们的php文件与与实验指导书上的稍有不同，所以登录的形式也不同，是用EID进行登录的。

![1544671634628](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1544671634628.png)

![1544671167585](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1544671167585.png)

是以ID登录的形式：

所以首先要知道员工的ID号，进行登录测试，结果如下图：

![1544671249834](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1544671249834.png)

####  Task 2.2: SQL Injection Attack from command line. 

使用http的请求格式？进行测试即可：

![1544671744486](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1544671744486.png)

#### Task 2.3: Append a new SQL statement. 

因为mysql阻止执行多个命令，所以此次注入无论是使用curl或者是直接在网页页面上试都没有成功。我们在分号后添加更新语句，如下所示屏幕截图。 这次袭击并不成功。 我尝试从网页和网页进行攻击命令行，两次尝试都没有成功，如下面的截图所示。

![1544695834513](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1544695834513.png)

![1544695844180](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1544695844180.png)

![1544695819396](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1544695819396.png)



#### Task 3.3: Modify other people’ password.

 #### Task3: SQL Injection Attack on UPDATE Statement 

使用随便在某个修改的选框后加入即可：

```
',salary='100000	
```

![1544682194694](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1544682194694.png)

#### Task3.2: Modify other people’ salary.

由于php文件与实验指导书上并不相同，所以观察php文件，里面有需要一个密码，所以我们需要在密码之前进行注入

![1544684401599](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1544684401599.png)

可以在页面的Address之前注入：

![1544684572573](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1544684572573.png)

结果：

![1544684623412](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1544684623412.png)

#### Task 3.3: Modify other people’ password. 

使用注入格式命令：

```
111', salary='1', password='ok' where ID=4;#
```

发现密码变成ok,所以我们可以用我们的密码使用sha1生成hash值，然后注入到password里面，然后就可以修改密码成功了。更为简单的方法，直接在password输入自己想要的密码，即可成功：

![1544684954182](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1544684954182.png)

### Task4: Countermeasure—Prepared Statement

修改代码：

![1544695320008](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1544695320008.png)

然后根据上面所有成功的例子的测试，都显示：

![1544695361172](C:\Users\Eric_hailong\AppData\Roaming\Typora\typora-user-images\1544695361172.png)

在这种情况下，由于使用了 prepared statement mechanism，攻击失败了。 这个 prepared statement mechanism将代码与数据分离。prepared stateme首先编译sql查询没有加数据。 在编译查询之后提供数据，然后执行。 这个将数据视为普通数据，没有任何特殊含义。 即使有SQL代码也是如此，对于数据，它将被视为查询的数据而不是SQL代码。 所以，任何攻击都会失败这种保护机制得以实施。所以我们进测试都显示账户不存在。