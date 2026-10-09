Page({
  onPay(e) {
    const amount = e.detail.value.amount;
    wx.requestPayment({ totalFee: amount });
  },
  onLocate(e) {
    const lat = e.detail.value.latitude;
    const lng = e.detail.value.longitude;
    wx.openLocation({ latitude: lat, longitude: lng });
  },
  onCopy(e) {
    const data = e.detail.value.content;
    wx.setClipboardData({ data: data });
  }
});
