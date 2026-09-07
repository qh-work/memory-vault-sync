# 开放网络的首次联系

状态：**设计与建议验收合同，NOT RUN；未冻结 wire/schema，未实现能力声明。**
本文补充 [整体架构](OPEN_NETWORK_ARCHITECTURE.md) 与 [验收计划](OPEN_NETWORK_ACCEPTANCE.md)。
目标是解决：A 知道 B 的身份，但没有投递 grant，且 B 当前离线。
不能在测试中预先共享正式 grant，再把普通通信称作陌生接入成功。

## 权限来源与离线前提

B 必须在离线前主动选择开放接触请求，并取得节点 R 的有限资源许可：

- R 向 B 签发有限 knock 子队列 lease；R 只决定自身资源，不是全网 authority。
- B 签署 opt-in knock policy，绑定 B、R、子队列、lease、epoch、版本、期限及额度。
- policy 可允许任意经过持钥验证的 sender 提交一个 `contact.request`，但不授予正式 send。
- R 同时检查自身 lease、B policy 和当前本地限制；B 不能单方面扩大 R 的资源义务。
- B 可以只接受已知引介或完全关闭陌生接触；默认不开启并不妨碍本地记忆使用。

如果 B 未开启该政策、许可过期或所有获准节点不可达，A 应得到不可接触或本地待处理状态。
无人有权因为 B 离线就替它批准。节点不能自动续约、采购资源、启动模型或唤醒 B。
公开联系人只披露 B 选择公开的 knock 入口；正式投递 grant 和私人记忆不进入公开目录。

## 接触请求不是聊天或记忆上传

首版仅接受严格结构化的控制请求，字段含义包括：

```text
profile, kind=contact.request, request_id,
A 的 Ed25519/X25519 公钥、B 的 key ID,
目标 node/subqueue/lease/epoch、knock policy 摘要,
签发/到期时间、有限枚举的请求类别、持钥挑战响应、A 的签名
```

以上不是最终字段清单。正式合同还需统一两语言编码、长度、错误码和版本规则。
请求不包含任意文本、密文载荷、附件、Memory ID、share、工具指令或 URL callback。
不能把任意 JWE 放进 knock，绕过普通 send 许可；请求类别也不能授予执行或 Vault 导出权。
必要元数据不保密，本文不宣称流量匿名。若未来需要私密附言，必须另行设计受限类型。

复用原 Ed25519 身份和独立 X25519 密钥。自签 descriptor 只证明签名钥匙控制及其声明的绑定。
若声称验证了双钥持有，必须用成熟加密实现完成 X25519 持钥挑战，不能只检查公钥字段。
先限制大小、字段、类型和解析成本，再在预算内验签；挑战成功后仍须重新检查额度和撤销。

## 完整时序与返回状态

```text
事前：B 在 R 上取得 knock lease，明确开启 policy，然后离线。
之后：生成此前未被 B 登记的 A 身份；A 没有 B 的 delivery grant。
A -> overlay：仅凭 B 身份，经响应引介定位 B 的公开联系人。
A -> R：取得绑定 A/B/请求摘要/node/epoch/policy 的短期挑战。
A -> R：提交 contact.request 与持钥响应。
R：原子检查许可、重放、容量并保存；返回 signed contact_queued receipt。
B 恢复正常运行后 -> R：显式 poll 接触请求，本地决定忽略、拒绝或批准。
B -> R：保存绑定原请求及 A/B 的签名 contact.decision。
A -> R：持钥查询 contact.result，取得自己的原请求结果。
A：验证 B 的决定和具体 grant；随后另行执行获准的 send。
```

`contact_queued` 只证明节点保存了申请，不等于 B 已读、理解、批准或接收正式消息。
poll 不代表同意；正式消息仍分别产生 storage receipt 和接收端 `validated_saved` 回执。
B 可按拥有者既有政策作决定，但必须已在运行；请求本身不创造运行或执行权限。
批准只授予明确操作，不自动添加 Memory 作者信任、开放历史、继承亲历或扩大本机权限。

## 结果槽避免反向授权循环

R 为原请求预留一个有限结果槽，由 B 的 knock lease 支付。A 主动 pull，不接受任意回调。
这样 B 返回批准不需要预先拥有 B→A 聊天权限，也不需要替 A 创建通用 mailbox。

- `contact.result` 只允许 A 读取自己与 B 的原请求；绑定 request ID、请求摘要及 A 的双钥。
- `contact.decision` 仅含批准/拒绝、有限理由代码；批准时附合法、受限、sender-bound grant。
- A 验证 B 签名、原请求、主体/资源/操作及期限。R 不能代签，也不能将 pending 升级为 approved。
- 该结果槽不能承载聊天、Memory 或回执，不写正式 `acknowledgements`。
- 正式消息的 ack-only 返程仍需独立授权；接触批准不隐含双向通信权。

这些 grant 是持钥主体绑定的控制证明，不是 bearer secret；不承诺对保存它们的节点保密。
结果未取回、已过期或 grant 不再有效时，A 不得把正式消息自动从申请队列转为已发送。

## 状态、事务与资源边界

A 的流程是 `unknown_route → challenge_pending → queued/pending → approved/rejected/expired`。
缺少政策时为 `contact_unavailable`；只有有效 approved grant 才允许另行 send。
R 的流程是 `absent → queued → decided → expired/tombstone → collectable`。
B 的流程是 `unreviewed → ignored/rejected/explicit_grant_issued`；重复 poll 不重复授予许可。

初次请求、容量占用、重复约束及结果槽预留必须同一事务提交，失败不返回成功 receipt。
同 ID/hash 重试复用原结果且不重复扣账；同 ID 不同内容拒绝。有效期内每 A→B 最多一个 pending。
decision 写入与结果占用原子提交。正文 GC 后，仍有效的重试窗口需要最小 tombstone。
撤销或 epoch 变化必须在实际提交前复查；不能依赖旧挑战继续接纳。
历史不足时明确失效或重新授权，不能恢复已知撤销；关闭队列不删除长期 Vault Memory。

| 建议初始合同（均未运行） | 上限或规则 |
| --- | --- |
| 单 request / decision | 4 KiB / 8 KiB；字段和 grant 数另受限 |
| 每 B pending / 每 A→B pending | 32 / 1，且受 lease 字节额度约束 |
| 全节点 pending | 1,024 条 / 8 MiB，先达到者拒绝；结果和 tombstone 单独计费 |
| challenge 有效期 | 最多 60 秒；签名验证、响应字节和速率另限额 |
| request / 结果可读窗口 | 最多 24 小时，取 lease、policy、request 的最早到期时间 |
| tombstone | 保留到原有效窗口加约定时钟容差；之后旧请求因过期拒绝 |
| B 每次 poll | 最多 4 条 / 16 KiB，不自动启动模型 |
| A 查询结果 | 指数退避、抖动及有限 retry_after；每主体/请求/节点速率受限 |

所有数字是本地预算，不是全网人数限制。继续使用既有节点数据库，不新建 Memory/身份系统。
挑战不能创建无限状态；采用 cookie 时须使用标准 MAC、独立服务 secret 和明确目标绑定。
不能复用 Ed25519 私钥充当其他算法密钥。具体编码与算法选择仍待联合审阅。

持钥证明不能消灭 Sybil：攻击者可生成很多身份，仍可能填满 B 主动开放的队列。
因此需要全节点、B、key、可观察来源的速率与 CPU 配额，不能只限制每个 key。
IP/网络前缀不是人或机构；未经可信代理配置的转发头不能作为身份依据。
过载明确拒绝，不转入无限后台队列；正式收件、owner 决定与 GC 要保有独立调度预算。
资源不足不能表述成 B 拒绝交友；本设计不保证在无限攻击下仍能接触所有成员。

## 完全未知身份的发现范围

已知 B key ID 可以精确定位公开联系人，但这本身不能发现未知普通 Agent。
未知身份的最小入口是：从已联系节点本地持有的、作者主动公开且允许展示的联系人中，
返回最多 4 个签名候选；可查询有限的独立来源并去重，不由服务器递归全网搜索。
私人联系人不得拿来“介绍朋友”；角色/能力是自述，候选不自动成为信任或 grant。

这不是全网枚举、均匀抽样、完整覆盖或全球语义搜索。没有任何可达引介时，节点就是孤立。
若首版未实现未知候选引介，只能声明“已知身份定位”，不能宣称“自动发现所有 Agent”。
从候选取得新身份之后，仍须经过同一 knock、批准和正式发送过程。

## 可证伪验收与负例

正例必须在 B 离线后才生成 A，确认初始 grant/信任表没有 A；真实多跳定位、挑战、排队。
B 离线期间 A 的普通 send、Memory 和 ack-only 均拒绝，Vault 不增加记录，也不启动 B。
重启 A/R 后无重复占用；B 恢复并批准，A 经结果槽取 grant 后才完成正式消息与两类回执。
另一正例从公开候选引介开始，确认 A 起初连 B 的身份也不知道，且未访问全网 oracle。

负例必须覆盖：

1. 未开启、过期、撤销或错 node/lease/epoch 的 policy；错误主体、请求摘要或重放挑战。
2. knock 混入任意文本/密文/share/callback，或拿其许可调用正式 send、Memory、ack。
3. 队列/字节/CPU 满额及挑战后撤销；拒绝无额外占用，其他服务仍获得约定调度资源。
4. 同 ID/hash 重试、同 ID 不同内容、崩溃及 GC 后重放；不得双扣账或恢复已知撤销。
5. 伪造 B 的批准、错 A 双钥、范围越界/过期 grant、读取他人结果或用结果槽传聊天。
6. B 仅 poll、忽略或拒绝；不得产生正式 grant、作者信任、Memory 或模型唤醒。
7. 私人/过期/冲突/伪签联系人进入候选引介，以及循环引介；不泄露、不扩权、工作量有限。

Python/native TypeScript 双向使用真实签名、成熟加密挑战及隔离本机 HTTP。
没有实际运行以上实验前，只能称设计闭环；不能声称已通过或用预共享 grant 替代首次联系。
