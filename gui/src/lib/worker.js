let list = []
let prop = null

let search = needle => needle ? list.filter(item => {
  let j = -1
  let heystack = (prop ? item[prop] : item)
  if (!heystack) return false
  heystack = heystack.toLowerCase()
  needle = needle.toLowerCase()
  for (let i = 0; i < needle.length; i++) {
    let l = needle.charAt(i)
    if (!l || l.match(/\s/)) continue

    j = heystack.indexOf(l, j + 1)
    if (j === -1)
      return false
  }
  return true
}) : list

onmessage = ({ data }) => {
  let { action, payload, key } = data

  if (action == 'update') {
    list = payload
    prop = key
  } else if (action == 'search') {
    postMessage(search(payload))
  }
}