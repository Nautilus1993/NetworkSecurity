[Rip Protocol Doc](./Rip.md)

1. 现在遇到的问题:

```python
    RipClient -->  CLS message --> RipServer
```

这个过程中, server收不到 message, 目前没有找到错误信息, 所以也不太明白要怎样 trouble shooting.

2. RipProtocol 中的modules结构:

可以参考 [RipStack](./RipProtocol/RipStack.py) 中的注释部分。

3. 我是这样运行的:

   + Term1:   python Chaperone.py
   + Term2:   python Gate.py gatekey1
   + Term3:   python Gate.py gatekey2
   + Term4:   python httpServer.py
   + Term5:   python httpClient.py

   因为httpClient有断开连接的操作,所以没有使用 echoTest.py.
