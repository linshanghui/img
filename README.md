# img
cdn图库
一个Github账号+一双手
建库
1.在Github首页的左边点击新建
2.完善仓库名后点击创建
3.上传图片
4.进入对应库中，点击上传文件
5.上传完毕后，生成外链
完成！
Github外链格式:

https://raw.githubusercontent.com/linshanghui/img/main/文件名

Jsdelivr外链格式：[https://cdn.jsdelivr.net/gh/用户名/仓库名/文件名](https://cdn.jsdelivr.net/gh/linshanghui/img/)

为爱发电（可能已失效）
kk外链格式:
https://kk.github.com/gh//linshanghui/img/文件名

#index.html
### 功能开发日志

---

#### **版本 1.0 - 基础功能**
**日期**：2023-10-01  
**功能描述**：  
1. 从 GitHub 仓库动态加载图片，通过 GitHub API 获取文件列表。  
2. 使用 jsDelivr CDN 加速图片加载。  
3. 在页面中展示图片及对应链接。  

**关键代码改动**：  
- 通过 `fetch` 调用 GitHub API 获取图片列表。  
- 动态生成 `<img>` 标签并插入到 DOM 中。  
- 使用 `https://cdn.jsdelivr.net/gh/<用户>/<仓库>/<路径>` 生成图片链接。  

---

#### **版本 1.1 - 分页功能**
**日期**：2023-10-05  
**功能描述**：  
1. 每页显示 5 张图片。  
2. 添加“上一页”和“下一页”按钮。  
3. 显示页码数字并支持跳转。  

**关键代码改动**：  
- 新增 `currentPage` 和 `imagesPerPage` 变量管理分页逻辑。  
- 添加 `updatePagination()` 更新分页按钮状态。  
- 使用 `slice()` 截取当前页的图片范围。  

---

#### **版本 1.2 - 链接复制与提示**
**日期**：2023-10-10  
**功能描述**：  
1. 点击图片名时复制链接到剪贴板。  
2. 显示“已复制链接”提示，3 秒后自动消失。  

**关键代码改动**：  
- 通过 `navigator.clipboard.writeText()` 实现复制功能。  
- 新增 `showCopyNotification()` 动态生成提示元素。  
- 阻止 `<a>` 标签的默认跳转行为（`e.preventDefault()`）。  

---

#### **版本 1.3 - 搜索功能**
**日期**：2023-10-15  
**功能描述**：  
1. 在页面顶部添加搜索框，支持按图片名称关键字过滤。  
2. 搜索结果实时更新分页和内容。  

**关键代码改动**：  
- 新增 `filteredImages` 变量存储过滤后的图片列表。  
- 监听搜索框的 `input` 事件，动态过滤 `allImages`。  
- 重置 `currentPage` 为 1 以确保从第一页开始显示。  

---

#### **版本 1.4 - Vercel 集成优化**
**日期**：2023-10-20  
**功能描述**：  
1. 将图片链接替换为 Vercel CDN 服务。  
2. 支持通过 Vercel 域名直接访问图片。  

**关键代码改动**：  
- 生成 Vercel 链接：`https://<域名>/<路径>/<文件名>`。  
- 更新 `allImages` 的 `url` 字段为 Vercel 格式。  

---

#### **版本 1.5 - 错误处理与样式优化**
**日期**：2023-10-25  
**功能描述**：  
1. 添加加载中和错误提示（如 API 调用失败）。  
2. 优化图片布局和分页按钮样式。  

**关键代码改动**：  
- 在 `loadImages()` 中捕获错误并显示 `<p class="error">`。  
- 使用 Flexbox 布局实现响应式图片排列。  
- 为分页按钮添加悬停效果和禁用状态样式。  

---

### 技术细节总结

#### 1. **核心逻辑**
- **数据获取**：通过 GitHub API (`/repos/{repo}/contents/{path}`) 获取文件列表。  
- **分页计算**：  
  ```javascript
  const startIndex = (currentPage - 1) * imagesPerPage;
  const imagesToShow = filteredImages.slice(startIndex, startIndex + imagesPerPage);
  ```

#### 2. **关键函数**
- `loadImages()`：初始化加载图片列表。  
- `showImagesForPage(page)`：渲染当前页的图片。  
- `updatePagination()`：更新分页按钮和页码状态。  
- `copyToClipboard(text)`：复制链接到剪贴板。  

#### 3. **依赖项**
- **GitHub API**：需确保仓库公开且路径正确。  
- **Vercel 部署**：需将仓库部署到 Vercel 并配置域名。  

---

### 已知问题与后续计划

#### **已知问题**
1. GitHub API 的速率限制（每小时 60 次请求）。  
   - **解决方案**：使用 GitHub Token 认证提升限制至 5000 次/小时。  
2. 跨域问题（CORS）可能影响本地开发。  
   - **解决方案**：通过 Vercel Serverless Function 代理 API 请求。  

#### **后续计划**
1. **图片懒加载**：仅加载可视区域内的图片以提升性能。  
2. **多仓库支持**：允许用户切换不同的 GitHub 仓库。  
3. **上传功能**：集成 GitHub API 实现网页端直接上传图片。  

---

### 部署说明

1. **Vercel 部署步骤**：  
   - 登录 Vercel，导入 GitHub 仓库。  
   - 配置构建命令（无需构建，直接部署静态 HTML）。  
   - 设置环境变量（如 `GITHUB_TOKEN`）。  

2. **代码仓库**：  
   ```bash
   git clone https://github.com/<用户>/<仓库>.git
   ```

---

通过以上迭代，系统已实现从基础图片加载到复杂交互的完整功能闭环。
