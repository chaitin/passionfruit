const { UIPasteboard } = ObjC.classes
const pasteboard = UIPasteboard.generalPasteboard()
const subject = 'pasteboard'

let current = null
setInterval(() => {
  const str = pasteboard.string().toString()
  if (str === current)
    return

  current = str
  send({
    subject,
    timestamp: new Date().getTime(),
    event: 'copy',
    arguments: str,
  })
}, 5 * 1000)
