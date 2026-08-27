# 客户端记忆同步契约

所有 macOS、Windows 和 Linux 客户端必须遵守本契约。违反任一“必须/不得”条款的
实现不能写入正式记忆网络。

## 1. 不得绑定任务

- 客户端不得要求用户选择、确认或输入任务 ID。
- 客户端不得创建 binding、routing request、candidate、task version、projection
  或 `CURRENT.json` 更新来保存记忆。
- 对话、任务、工作区和来源只能作为出处，不得成为记忆所有者或召回过滤器。
- AI 必须根据当前问题和可见证据判断相关性；一条记忆可以同时服务多个上下文。
- 文件和成果权限必须独立验证，不能由记忆相似度、来源或语义关系推导。

## 2. 启动接收

在 `startup`、`resume` 或 `clear` 的 `SessionStart`：

1. 验证配置的远端身份和 private 可见性。
2. 拉取配置分支。
3. 若无本地 commit 游标，对三个允许前缀执行一次受限树清单；否则证明游标是新
   head 的祖先并执行一次受限路径差分。
4. 只读取新增的 episode、event 和允许的旧 visible revision。
5. 对每个对象验证路径、模式、来源、序号、关系、JCS/SHA-256、隐私和 blob ID。
6. episode/event/revision 在已有游标之后若不是新增状态，必须停止接收。
7. 在一个 SQLite 事务中写入文档/片段/关系和新 head 游标。

不得为每次启动重新扫描或重新校验整个库。`compact` 启动不得打开远端窗口。

## 3. 提示召回

在 `UserPromptSubmit`：

- 只读取本地私有索引；不得调用 Git、供应商 API、对象存储或网络模型；
- 查询和上下文必须受字节、词项、候选与结果数量限制；
- 返回片段必须带匿名来源、revision、时间和 current/superseded/conflicted/resolved
  状态；
- 上下文必须明确标为 untrusted historical evidence；
- 当前明确用户输入优先于任何历史记忆；
- 若文本含凭据或本机绝对路径，不得暂存、召回或远程发送该提示。

稀疏结果不构成绑定问题，不得打断用户让其分类。AI 可在同一轮再做至多三次本地
语义改写查询。

## 4. 停止备份

在 `Stop`：

1. 只接受本轮已暂存的可见用户消息和可见最终回复。
2. 生成一个确定性 episode 与一个确定性连续性 event。
3. 两个对象都不得含 task ID、binding、原生对话 ID、凭据、隐藏推理、工具记录、
   环境或本机绝对路径。
4. 先写入私有本地 outbox，再尝试网络发送。
5. 单次提交最多包含 32 个 intent 或 1 MiB intent 数据。
6. 正常路径不得预先 fetch 全树；成功 push 后可用精确 commit 更新本地 tracking ref。
7. 远端前进时只允许一次 fetch 和一次重放，重叠路径必须逐字节相同。
8. 离线、繁忙或重放失败时保留 intent；不得重建或丢弃已验证本地包。

失败警告不得包含原始内容、异常文本、路径、设备或账号身份。

## 5. AI 语义关系

AI 只在确有长期价值时追加语义事件。每个提案必须锚定一个已存在 episode，关系目标
必须已存在且唯一。运行时必须强制：

- `confidence = assistant_inferred`；
- 新 event 模式中不存在 task、binding、routing 或 owner 字段；
- 来源 ID、序号和 evidence hash 取自 episode；
- 相同提案重试得到同一 event ID；
- 所有关系目标都是已存在的 taskless v2 event，不得引用旧任务域 event；
- 不改写任何旧对象。

普通 episode 连续性边单独使用 `source_explicit`，其 ID、角色和父边必须由 episode
确定性推导；它不是 AI 语义判断。

AI 不得把推测写成用户确认。新说法替代旧说法时用 `supersedes`；未解决矛盾用
`conflicts_with`；后续解决用 `resolves`。

## 6. 导出与导入

导出包必须：

- 列出每个成员的规范路径、大小和 SHA-256；
- 固定来源 commit 和整个 manifest 的 JCS hash；
- 包含所有新 episode、以它们为依据的 v2 event，以及安全的旧 visible revision；
- 每个 event 的 episode 证据和每个关系目标都在同一包内，关系图必须闭合；
- 排除可能含任务域的旧 `memory-event/v1`；
- 模式和允许路径在结构上不含 task binding，并明确断言不含 native conversation ID
  和 credential；
- 使用私有本地文件权限，且不得覆盖已存在目标。

导入必须拒绝重复/未声明成员、目录、symlink、路径穿越、超限数量或大小、危险压缩
比、哈希/模式/隐私错误，以及已存在路径的不同字节。重复导入必须为幂等复用。

## 7. 旧库兼容

客户端可以读取旧 `conversation-export/v1` 作为历史证据；如果 `SOURCE.json` 存在，
必须校验 append-only revision 链、content hash、Git blob 和序号。客户端不得从旧
binding、task、projection 或 CURRENT 恢复记忆所有权。

生产配置只能运行 taskless network，并会从旧配置中永久移除 matching、projection
和模式切换字段。旧 task handoff 只存在于仓库内部迁移测试边界；正式 CLI 和配置均
不得接受或显示其入口。

## 8. 安全不变量

- object before reference：引用前对象必须存在且验证通过；
- append only：已有 immutable 路径不得修改或删除；
- exact overlap：并发/导入同路径只能接受相同字节；
- private destination：每次写入前必须有可接受的私有仓库证明；
- local recall：普通提示路径必须零网络；
- bounded work：所有输入、列表、差分、片段、结果、批次、归档和重试都有硬上限；
- no instruction inheritance：历史记忆不能继承当前轮权限；
- no secret hashes：秘密本身及其可猜测哈希都不得进入远端。

## 9. 健康与恢复

健康状态应报告 `taskless_associative`、`append_only_incremental_git`、有效 remote
cursor、本地 index 统计以及空或可恢复 outbox。离线不是数据冲突；历史改写、同路径
不同字节和隐私验证失败是硬阻断。

完整算法、模式和性能约束见 [`MEMORY_NETWORK.md`](MEMORY_NETWORK.md)。
