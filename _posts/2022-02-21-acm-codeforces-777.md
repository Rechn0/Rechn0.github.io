---
layout: post
title: Codeforces Round#777 (Div. 2)
author: Rechn0
date: 2022-03-12 20:00 +0800
last_modified_at: 2022-03-12 20:00 +0800
tags: [acm, codeforces]
categories: [acm, practice]
toc:  true
math:  true
---

Codeforces #777 题解

这次带上了大佬前来验题xs，并公开珍贵的代码资源供参考

---

## A.Madoka and Math Dad

[Problem](https://codeforces.com/contest/1647/problem/A)

在给定条件下要找到最大的数字，考虑到数字位数较多的方案更优

由于不能使用0，也不能出现相邻的相同数字，因此使用1|2序列构造即可得到答案

首先令 \\\( ans= \frac{n}{3} \* '21' \\\) ，进行分类讨论

* \\\( n=0 \pmod{3} \\\) 则ans即为答案
* \\\( n=1 \pmod{3} \\\) 则 \\\( ans='1'+ans \\\)
* \\\( n=2 \pmod{3} \\\) 则 \\\( ans=ans+'2' \\\)

**cpp-version**

```cpp
int t,n;
inline void Main()
{
	cin>>t;
	while(t--)
	{
		cin>>n;
		string ans="";
		rep(i,1,n/3)ans+="21";
		if(n%3==1)ans="1"+ans;
		if(n%3==2)ans=ans+"2";
		cout<<ans<<endl;
	}
	return;
}
```

**python3-version**

```python
n = int(input())
num_list = []
cnt = 0
while cnt < n:
    num_list.append(int(input()))
    cnt += 1
for num in num_list:
    res = num % 3
    mul = int(num / 3)
    if res == 0:
        print(mul * "21")
    elif res == 1:
        print("1" + mul * "21")
    else:
        print(mul * "21" + "2")
```

## B.Madoka and the Elegant Gift

[Problem](https://codeforces.com/contest/1647/problem/B)

根据题目给出的定义，nice矩形即为某个不能再扩张的最大全1矩形

分析可以发现，如果某一片连续的全1区域不是规则的矩形，即这篇区域是在矩形的基础上增加了一些1方格，则该区域一定可以找到至少两个nice矩形相交

> 简单的例子：
> 
> $$
> \begin{bmatrix} 1 & 1 & 0 \\ 1 & 1 & 1 \\ 1 & 1 & 0 \end{bmatrix} \rightarrow \begin{bmatrix} 1 & 1 & * \\ 1 & 1 & * \\ 1 & 1 & * \end{bmatrix} and \begin{bmatrix} * & * & * \\ 1 & 1 & 1 \\ * & * & * \end{bmatrix}
> $$
> 
> 可以推广到更复杂的情况
>
> 结论：某个01矩阵是elegant的，当且仅当矩阵中的1方格构成了若干个规则的矩形

因此只需要判断矩阵中的1区域是否为标准的矩形即可

对于每一个1方格，分别向右向下搜索找到最长连续的1，作为当前子矩阵的n与m。只需要判断：

* 子矩阵中是否全1
* 子矩阵的边界是否存在1

即可得到当前子矩阵的合法性。对所有遍历过的1方格打标记，防止多次遍历

**cpp-version**

```cpp
int t,n,m;
char A[200][200];
int mark[200][200];
inline bool check(int si,int sj)
{
	int nown=0,nowm=0;
	while(si+nown<=n&&A[si+nown][sj]=='1')++nown;
	while(sj+nowm<=m&&A[si][sj+nowm]=='1')++nowm;
	rep(i,si,si+nown-1)rep(j,sj,sj+nowm-1)
	{
		if(A[i][j]=='0')return false;
		mark[i][j]=1;
	}
	rep(i,si,si+nown-1)
	{
		if(sj-1>=1&&A[i][sj-1]=='1')return false;
		if(sj+nowm<=m&&A[i][sj+nowm]=='1')return false;
	}
	rep(j,sj,sj+nowm-1)
	{
		if(si-1>=1&&A[si-1][j]=='1')return false;
		if(si+nown<=n&&A[si+nown][j]=='1')return false;
	}
	return true;
}
inline void Main()
{
	cin>>t;
	while(t--)
	{
		cin>>n>>m;
		rep(i,1,n)rep(j,1,m)
		{
			cin>>A[i][j];
			mark[i][j]=0;
		}
		bool flag=true;
		rep(i,1,n)rep(j,1,m)
		{
			if(A[i][j]=='0'||mark[i][j]==1)continue;
			if(!check(i,j))flag=false;
		}
		if(flag)cout<<"Yes"<<endl;
		else cout<<"No"<<endl;
	}
	return;
}
```

**python3-version**

```python
n = int(input())
ans_list = []
 
cnt = 0
 
while cnt < n:
    table = []
    tmp = input().split(' ')
    rows = int(tmp[0])
    cols = int(tmp[1])
    for row in range(rows):
        table.append([])
        num_str = str(input())
        for num in num_str:
            table[row].append(int(num))
    mark = []
    for row in range(rows):
        mark.append([])
        for col in range(cols):
            mark[row].append(0)
 
 
    def checkLen(r, c):
        cnt_col = 0
        while c + cnt_col <= cols - 1 and table[r][c + cnt_col] == 1:
            cnt_col += 1
 
        cnt_row = 0
        while r + cnt_row <= rows - 1 and table[r + cnt_row][c] == 1:
            cnt_row += 1
 
        return cnt_row, cnt_col
 
 
    rlen = 0
    clen = 0
    f = 0
    for row in range(rows):
        for col in range(cols):
            if table[row][col] == 0:
                continue
            if mark[row][col] == 0:
                rlen, clen = checkLen(row, col)
                for i in range(rlen):
                    for j in range(clen):
                        mark[row + i][col + j] = 1
                        if table[row + i][col + j] == 0:
                            f = 1
                            break
                        elif col - 1 >= 0 and table[row + i][col - 1] == 1:
                            f = 1
                            break
                        elif col + clen <= cols - 1 and table[row + i][col + clen] == 1:
                             f = 1
                             break
                        elif row - 1 >= 0 and table[row - 1][j + col] == 1:
                            f = 1
                            break
                        elif row + rlen <= rows - 1 and table[row + rlen][j + col] == 1:
                                f = 1
                                break
 
    if f == 1:
        ans_list.append('NO')
    else:
        ans_list.append('YES')
 
    cnt += 1
for ans in ans_list:
    print(ans)
```

## C.Madoka and Childish Pranks

[Problem](https://codeforces.com/contest/1647/problem/C)

分析题目的操作可以发现，矩阵左上角的位置(1,1)是无法被染成黑色(1方格)的，如果目标矩阵的左上角为黑色则无解

考虑一种操作，对矩阵 \\\( (i,j) \rightarrow (i+1,j) \\\) 进行染色，即将 \\\( (i,j) \\\) 染为白色(0方格)，将 \\\( (i+1,j) \\\) 染为黑色

$$
opt_1 = \begin{bmatrix} 0 \\ 1 \end{bmatrix}
$$

枚举每一列，从下向上遍历该列的方格。如果位置 \\\( (i,j) \\\) 应该染为黑色，则对 \\\( (i-1,j) \rightarrow (i,j) \\\) 进行染色，即可将该点变为黑色。使用这种操作，可以将除了第一行的所有方格进行正确的染色

对于第一行考虑另一种操作，对矩阵 \\\( (1,j) \rightarrow (1,j+1) \\\) 进行染色，即将 \\\( (1,j) \\\) 染为白色， \\\( (1,j+1) \\\) 染为黑色

$$
opt_2 = \begin{bmatrix} 0 & 1 \end{bmatrix}
$$

同理右向左遍历第一行的方格进行染色，即可将整个矩阵合法染色

在极限情况下，该方案需要进行 \\\( n \* m \\\) 次染色，符合题目要求

**cpp-version**

```cpp
int t,n,m;
char A[200][200];
int cnt;
struct op
{
	int x1,y1,x2,y2;
	op(int a=0,int b=0,int c=0,int d=0)
	{
		x1=a,y1=b,x2=c,y2=d;
	}
}ans[20004];
inline void Main()
{
	cin>>t;
	while(t--)
	{
		cin>>n>>m;
		rep(i,1,n)rep(j,1,m)cin>>A[i][j];
		if(A[1][1]=='1')cout<<"-1"<<endl;
		else
		{
			cnt=0;
			rep(j,1,m)per(i,n,2)if(A[i][j]=='1')
                ans[++cnt]=hzq(i-1,j,i,j);
            per(j,m,2)if(A[1][j]=='1')
                ans[++cnt]=hzq(1,j-1,1,j);
			cout<<cnt<<endl;
			rep(i,1,cnt)
			{
				cout<<ans[i].x1<<sep<<ans[i].y1<<sep;
				cout<<ans[i].x2<<sep<<ans[i].y2<<endl;
			}
		}
	}
	return;
}
```

**python3-version**

```python
n = int(input())
 
cnt = 0
 
while cnt < n:
    table = []
    tmp = input().split(' ')
    rows = int(tmp[0])
    cols = int(tmp[1])
    for row in range(rows):
        table.append([])
        num_str = str(input())
        for num in num_str:
            table[row].append(int(num))
 
    if table[0][0] == 1:
        print(-1)
    else:
        oper_list = []
        for col in range(cols):
            for row in range(1,rows):
                if table[rows-row][col] == 1:
                    oper_list.append([rows-row, col + 1, rows-row + 1, col + 1])
        for col in range(1,cols):
            if table[0][cols-col] == 1:
                oper_list.append([1, cols-col, 1, cols-col + 1])
        print(len(oper_list))
        for i in oper_list:
            print(i[0], i[1], i[2], i[3])
    cnt += 1
```

## D.Madoka and the Best School in Russia

[Problem](https://codeforces.com/contest/1647/problem/D)

对于good与beautiful的定义分析如下：

* x是good的，则 \\\( x=k \* d \\\)
* x是beautiful的，则 \\\( x=k\*d, k \neq 0 \pmod{d} \\\)

对于给定的x与d，题目要求寻找是否存在至少两种方案，将x分解为若干beautiful数

考虑将x分为 \\\( res \* d^i, res \neq 0 \pmod{d} \\\) ，则一定存在下列方案：

$$
res \* d, d, ..., d
$$

因此只需要判断是否存在第二种方案即可。这里使用简单的分类讨论。

~~虽然赛时遗忘了一种情况，哈哈~~

\* 以下条件使用递进关系，即讨论i条件时，1~i-1条件均不满足

**1.i=1**

此时 \\\( x=res \* d \\\)，因此只有**x本身**这一个方案

**2.res=a \* b**

当res可以分解为两个不为1的整数时(即res不为1或者一个素数)，可以得到第二种方案：

$$
a \* d, b \* d, d, ..., d
$$

**3.prime d**

若res无法分解，且d为素数时，无法找到其他方案

\* 否则，可以考虑将d分解，以找到新的方案。下列情况对该情况进行讨论

**4.i==2**

可以发现在该情况下，无法将某一个d分解后得到新的有效解

**5.i>3**

此时考虑将一个d分解为 \\\( d_1, d_2 \\\)，则第二种方案：

$$
res \* d, d_1 \* d, d_2 \* d, ..., d
$$

**6.i==3**

最后一种情况： \\\( x=res \* d^3,  d=d_1 \* d_2, prime:res \\\)

易知如果 \\\( res \neq d_1, d_2 \\\)，则第二种方案：

$$
res \* d_1 \* d, d_2 \* d
$$

只要能够找到d的一种分解方案，使得 \\\( res \* d_1 \neq d \\\) 即可

然而，如果 \\\( d = d_1 \* d_2 = res \* res \\\) ，则无法找到第二种方案，需要进行最后的判断即可

**cpp-version**

```cpp
int t,x,d,res,cntd;
inline bool check(int x)
{
	if(x<=3)return true;
	for(int i=2;i*i<=x;++i)
	{
		if(x%i==0)return false;
	}
	return true;
}
inline bool func()
{
	if(cntd<=1)return false;
	//cntd>=2
	if(check(res)==false)return true;
	//prime res,cntd>=2
	if(check(d)==true)return false;
	//non-prime d,prime res,cntd>=2
	if(cntd>3)return true;
	//non-prime d,prime res,cntd=2,3
	if(cntd==2)return false;
	//non-prime d,prime res,cntd=3
	if(res*res%d==0)return false;
	return true;
}
inline void Main()
{
	cin>>t;
	while(t--)
	{
		cin>>x>>d;
		res=x,cntd=0;
		while(res%d==0)
		{
			++cntd;
			res/=d;
		}
		if(func())cout<<"Yes"<<endl;
		else cout<<"No"<<endl;
	}
	return;
}
```

**python3-version**

```python
t = int(input())
def check(x):
    if x <= 3:
        return True
    i = 2
    while i * i <= x:
        if x % i == 0:
            return False
        i += 1
    return True
while t:
    t -= 1
    x, d = [int(i) for i in input().split(' ')]
    a, di = x, 0
    while a % d == 0:
        a, di = a // d, di + 1
    flag = True
    if di <= 1:
        flag = False
    elif check(a) == False:
        flag = True
    elif check(d) == True:
        flag = False
    elif di > 3:
        flag = True
    elif di == 2:
        flag = False
    elif a * a == d:
        flag = False

    if flag:
        print("Yes")
    else:
        print("No")
```

---