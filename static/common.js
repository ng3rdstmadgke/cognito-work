class CommonUtils {
  static getRandomString(length) {
    const S="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return Array.from(crypto.getRandomValues(new Uint8Array(length))).map((n)=>S[n%S.length]).join('')
  }
  /**
    * トークンを表示する
    */
  static displayIdToken(keys) {
    for (let key of keys) {
      let data = JSON.parse(localStorage.getItem(key))
      if (data) {
        let table = document.getElementById(key)
        Object.entries(data).forEach(([k, v]) => {
          table.insertAdjacentHTML("beforeend", `<tr><td>${k}</td><td width="1000">${v}</td></tr>`)
        })
      }
    }
  }
}