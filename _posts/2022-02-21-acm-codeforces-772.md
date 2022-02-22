---
layout: post
title: Codeforces Round#772 (Div. 2)
author: Rechn0
date: 2022-02-21 13:30 +0800
last_modified_at: 2022-02-22 11:30 +0800
tags: [acm, codeforces]
categories: [acm, practice]
toc:  true
math:  true
---

Codeforces #772 题解

摸鱼摸了很久很久，昨天随意练习一下

人菜，以后acm练的比较少了，随缘补题

---

## A. Min Or Sum

[Problem](https://codeforces.com/contest/1635/problem/A)

每次操作前后两数或运算的结果相同，故对于第i位二进制位：

* 若 \\\( a_{i}, a_{j} \\\) 均为0，则 \\\( x, y \\\) 也为0即可
* 若 \\\( a_{i}, a_{j} \\\) 存在至少一个1，则 \\\( x, y \\\) 中只保留一个1，可以令数组和变小

因此对整个数组，依次考虑每个二进制位。若每个元素该位为0，则无事发生。若存在元素该位为1，则只保留一个元素使该位为1即可，此时 \\\( ans+=2^i \\\)


```cpp
int t,n,a[N];
inline void Main()
{
	cin>>t;
	while(t--)
	{
		cin>>n;
		rep(i,1,n)cin>>a[i];
		int ans=0;
		rep(k,0,30)
			rep(i,1,n)
				if((a[i]>>k)&1)
				{
					ans+=1<<k;
					break;
				}
		cout<<ans<<endl;
	}
	return;
}
```

## B. Avoid Local Maximums

[Problem](https://codeforces.com/contest/1635/problem/B)

首先找出数组中存在的局部极大值。已知对于i位置的局部极大值，只需要令其某个相邻元素与它相等即可

对于i-1、i+1两相邻位置的局部极大值，将i位置元素修改为两极大值中较大的一个，即可消除两个局部极大值，此策略较优

```cpp
int t,n,a[N],b[N];
inline void Main()
{
	cin>>t;
	while(t--)
	{
		cin>>n;
		int cnt=0;
		rep(i,1,n)
		{
			cin>>a[i];
			b[i]=0;
		}
		rep(i,2,n-1)
		{
			if(a[i]>a[i-1]&&a[i]>a[i+1])b[i]=1;
		}
		rep(i,1,n)
		{
			if(b[i-1]==1&&b[i+1]==1)
			{
				++cnt;
				a[i]=max(a[i-1],a[i+1]);
				b[i-1]=b[i+1]=0;
			}
			else if(b[i-1]==1)
			{
				++cnt;
				a[i]=a[i-1];
				b[i-1]=0;
			}
		}
		cout<<cnt<<endl;
		rep(i,1,n)cout<<a[i]<<sep;
		cout<<endl;
	}
	return;
}
```

## C. Differential Sorting

[Problem](https://codeforces.com/contest/1635/problem/C)

观察发现元素 \\\( a_{n-1}, a_{n} \\\) 是无法被修改的，\\\( a_{n-2} \\\) 仅能被修改为 \\\( a_{n-1}-a_{n} \\\)

因此，首先判断最后两个元素是否单调不减，然后考虑将所有其他元素均修改为 \\\( a_{n-1}-a_{n} \\\) 的可行性即可

```cpp
int t,n,a[N];
inline void Main()
{
	cin>>t;
	while(t--)
	{
		cin>>n;
		bool flag=true;
		rep(i,1,n)cin>>a[i];
		rep(i,2,n)
		{
			if(a[i-1]>a[i])flag=false;
		}
		if(a[n-1]>a[n]||(a[n-1]-a[n])>a[n-1])cout<<"-1"<<endl;
		else if(flag)cout<<"0"<<endl;
		else
		{
			cout<<n-2<<endl;
			rep(i,1,n-2)cout<<i<<sep<<n-1<<sep<<n<<endl;
		}
	}
	return;
}
```

## D. Infinite Set

[Problem](https://codeforces.com/contest/1635/problem/D)

考虑无限集生成的两种操作

1. \\\( x \rightarrow 2*x+1 \\\) 即二进制最低位增加一个1
2. \\\( x \rightarrow 4*x \\\) 即二进制最低位增加两个0

本题求解小于\\\( 2^p \\\)的无限集元素数，即二进制位不超过p位的元素数

对于二进制位数len的元素\\\( a_{i} \\\)，它可以产生的元素数为\\\( f[p-i] \\\)，其中：

$$
f[0]=1, f[1]=2
$$

$$
f[i]=f[i-1]+f[i-2]+1
$$

对于元素\\\( a_{i} \\\)与\\\( a_{j} \\\)，若\\\( a_{j} \\\)删除若干个低位的00/1后可以得到\\\( a_{i} \\\)，则\\\( a_{j} \\\)产生的元素均可由\\\( a_{i} \\\)产生，此时不统计\\\( a_{j} \\\)对答案的贡献即可

```cpp
int n,p,a[N];
map<int,bool>ma;
int func[N];
inline void init(int n)
{
	func[0]=1;
	func[1]=2;
	rep(i,2,n)func[i]=(func[i-1]+func[i-2]+1)%mod;
}
bool che(int x)
{
	if(ma[x])return false;
	if(x==0)return true;
	if(x&1)return che(x>>1);
	else
	{
		if(x%4!=0)return true;
		return che(x>>2);
	}
}
inline void Main()
{
	init(200001);
	cin>>n>>p;
	rep(i,1,n)cin>>a[i];
	sort(a+1,a+n+1);
	
	int ans=0;
	rep(i,1,n)
	{
		int lim=0,flag=true;
		while(1)
		{
			if((1<<lim)>a[i])break;
			++lim;
		}
		
		if(lim>p)flag=false;
		else flag=che(a[i]);
		
		ma[a[i]]=true;
		if(flag)ans=(ans+func[p-lim])%mod;
	}
	cout<<ans<<endl;
	return;
}
```

---