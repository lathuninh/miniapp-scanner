function request(url, data) {
  const options = { method: "GET" };
  return wx.request({ url: url, data: data });
}

function navigate(path) {
  wx.navigateTo({ url: path });
}

module.exports = { request, navigate };