const { request, navigate } = require("../../utils/request");

Page({
  onLoad(options) {
    const id = options.id;
    const a = id;
    const b = a;
    request("/api/detail?id=" + b, {});
    navigate("/pages/other?id=" + id);
  },
});