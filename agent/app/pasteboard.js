const subject = 'pasteboard'

let current = null
let timer = null

export function start() {
  const pasteboard = ObjC.classes.UIPasteboard.generalPasteboard()
  timer = setInterval(() => {
    let str = pasteboard.string()
    if (!str)
      return
    str = str.toString()
    if (str === current)
      return

    current = str
    send({
      subject,
      timestamp: new Date().getTime(),
      event: 'copy',
      arguments: str
    })
  }, 5 * 1000)
}

export function stop() {
  if (timer != null)
    clearInterval(timer)
}
