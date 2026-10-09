# 一、执行摘要

本次针对 `noodle_shop_procedures-master` 小程序项目开展安全扫描，覆盖 52 个文件、5774 行代码，共产生 4 条原始报警，均为 **低危** 级别，无高危、中危问题。

4 条报警全部集中在 **污点传播类** 问题，具体表现为：用户可控数据（`e.currentTarget.dataset.id`）未经编码或校验，直接通过字符串拼接进入 `wx.navigateTo` 的跳转 URL，涉及 `pages/category/category.js` 与 `pages/index/index.js` 两个页面共 3 处代码点。

经人工研判：

- 3 处判定为 **TP（真实问题）**，置信度 75，存在参数注入风险；
- 1 处判定为 **UNCERTAIN**，置信度 55，需结合上下文进一步确认。

整体风险可控，但建议在短期内完成统一修复，避免用户可控值污染跳转路径或查询参数，防止越权访问、参数篡改或页面异常跳转。

---

# 二、风险评级

| 维度 | 评估结果 |
| --- | --- |
| 整体风险等级 | **低危** |
| 高危问题 | 0 |
| 中危问题 | 0 |
| 低危问题 | 4 |
| 主要风险类型 | 污点传播（用户输入 → `wx.navigateTo`） |
| 影响范围 | 2 个页面文件，3 处代码点 |
| 可利用性 | 较低（小程序跳转受限于内部页面白名单） |
| 潜在影响 | 参数注入、页面异常跳转、query 参数篡改 |

**结论**：当前无紧急安全事件，但存在代码规范与输入校验缺失问题，建议纳入常规迭代修复。

---

# 三、重点问题分析

## 问题 1：`pages/category/category.js:111` — 用户输入拼接跳转 URL

- **风险等级**：低危
- **研判结论**：TP（置信度 75）
- **污点路径**：`e.currentTarget.dataset.id`（用户可控） → 字符串拼接 → `wx.navigateTo`
- **问题描述**：`dataset.id` 来源于页面元素属性，可被用户通过调试工具或构造点击事件篡改，直接拼接进跳转 URL，未做 `encodeURIComponent` 或白名单校验。
- **潜在影响**：攻击者可构造恶意 `id` 值（如包含 `&`、`?`、`../` 等特殊字符），造成 query 参数注入或跳转到非预期页面。

## 问题 2：`pages/index/index.js:44` — 用户输入拼接跳转 URL

- **风险等级**：低危
- **研判结论**：TP（置信度 75）
- **污点路径**：`e.currentTarget.dataset.id` → 字符串拼接 → `wx.navigateTo`
- **问题描述**：与问题 1 同类，`dataset.id` 未编码直接拼接进跳转路径。
- **潜在影响**：参数注入、跳转路径污染。

## 问题 3：`pages/index/index.js:50` — 用户输入拼接跳转 URL

- **风险等级**：低危
- **研判结论**：UNCERTAIN（置信度 55）
- **污点路径**：`e.currentTarget.dataset.id` → 字符串拼接 → `wx.navigateTo`
- **问题描述**：小程序 `navigateTo` 仅支持内部页面跳转，若 `dataset.id` 仅用于页面路径拼接且路径固定，则实际风险有限；但若用于 query 参数，则仍存在注入风险。
- **建议**：需确认该处 `dataset.id` 的具体用途，统一按 TP 处理并修复。

**共性问题**：3 处代码均缺少对用户可控输入的编码与校验，属于典型的「信任前端数据」缺陷。

---

# 四、分阶段修复方案

## 🔥 紧急（24h）

1. **确认问题 3 的实际用途**：检查 `pages/index/index.js:50` 处 `dataset.id` 是否用于 query 参数或路径拼接，明确风险等级。
2. **临时缓解**：在 3 处 `wx.navigateTo` 调用前，对 `dataset.id` 增加 `encodeURIComponent` 编码，快速阻断注入路径。

## ⚡ 短期（1 周）

1. **统一封装跳转工具函数**：在 `utils/` 下新增 `navigate.js`，集中处理 URL 拼接、参数编码与白名单校验。
2. **替换全部 `wx.navigateTo` 调用**：将 3 处问题点改为调用封装函数，避免重复缺陷。
3. **增加输入校验**：
   - 若 `id` 为数字，使用 `parseInt(id, 10)` 强转并校验 `NaN`；
   - 若 `id` 为字符串，使用白名单正则（如 `^[a-zA-Z0-9_-]+$`）过滤。
4. **代码评审**：对全项目 `wx.navigateTo` / `wx.redirectTo` / `wx.switchTab` 调用做一次全面排查。

## 📅 中期（1 月）

1. **引入静态扫描规则**：将「用户输入 → 跳转 API」纳入 CI 流程，防止回归。
2. **建立前端输入校验规范**：明确所有来自 `dataset`、`query`、`storage` 的数据在使用前必须校验或编码。
3. **安全编码培训**：对开发团队开展小程序安全编码培训，重点讲解污点传播与输入校验。
4. **定期复扫**：每月执行一次全量扫描，跟踪修复效果。

---

# 五、代码修复示例

## 修复前（存在风险）

```javascript
// pages/index/index.js
onTapItem(e) {
  const id = e.currentTarget.dataset.id;
  wx.navigateTo({
    url: '/pages/detail/detail?id=' + id
  });
}
```

## 修复方案一：直接编码（快速修复）

```javascript
onTapItem(e) {
  const id = e.currentTarget.dataset.id;
  wx.navigateTo({
    url: '/pages/detail/detail?id=' + encodeURIComponent(id)
  });
}
```

## 修复方案二：数字 ID 强转 + 校验（推荐）

```javascript
onTapItem(e) {
  const rawId = e.currentTarget.dataset.id;
  const id = parseInt(rawId, 10);
  if (Number.isNaN(id) || id <= 0) {
    wx.showToast({ title: '参数错误', icon: 'none' });
    return;
  }
  wx.navigateTo({
    url: `/pages/detail/detail?id=${id}`
  });
}
```

## 修复方案三：统一封装跳转工具（最佳实践）

```javascript
// utils/navigate.js
const SAFE_ID_REGEX = /^[a-zA-Z0-9_-]+$/;

function safeNavigateTo(path, params = {}) {
  const query = Object.keys(params)
    .map(key => {
      const value = String(params[key]);
      if (!SAFE_ID_REGEX.test(value)) {
        throw new Error(`非法参数: ${key}`);
      }
      return `${encodeURIComponent(key)}=${encodeURIComponent(value)}`;
    })
    .join('&');

  const url = query ? `${path}?${query}` : path;
  wx.navigateTo({ url });
}

module.exports = { safeNavigateTo };
```

```javascript
// pages/index/index.js
const { safeNavigateTo } = require('../../utils/navigate.js');

onTapItem(e) {
  const id = e.currentTarget.dataset.id;
  try {
    safeNavigateTo('/pages/detail/detail', { id });
  } catch (err) {
    wx.showToast({ title: '参数错误', icon: 'none' });
  }
}
```

**修复要点总结**：

1. 所有用户可控输入在拼接 URL 前必须经过 `encodeURIComponent` 编码；
2. 优先使用 `parseInt` 或白名单正则进行类型与格式校验；
3. 通过统一工具函数收敛跳转逻辑，降低遗漏风险；
4. 校验失败时给出明确提示，避免静默失败。