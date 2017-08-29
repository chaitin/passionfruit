export function matcher(items, prop) {
  return needle => {
    if (!needle)
      return items

    return items.filter(item => {
      let j = -1
      let heystack = (prop ? item[prop] : item).toLowerCase()
      for (let i = 0; i < needle.length; i++) {
        let l = needle.charAt(i)
        if (!l || l.match(/\s/)) continue

        j = heystack.indexOf(l, j + 1)
        if (j === -1)
          return false
      }
      return true
    })
  }
}

export function debounce(func, wait, immediate) {
  let timeout
  return function() {
    let context = this, args = arguments
    let later = function() {
      timeout = null
      if (!immediate) func.apply(context, args)
    }
    let callNow = immediate && !timeout
    clearTimeout(timeout)
    timeout = setTimeout(later, wait || 400)
    if (callNow) func.apply(context, args)
  }
}