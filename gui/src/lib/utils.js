export function matcher(items, prop) {
  return needle => {
    if (!needle)
      return items

    return items.filter(item => {
      let j = -1
      let heystack = item[prop].toLowerCase()
      for (let i = 0; i < needle.length; i++) {
        let l = needle[i]
        if (l.match(/\s/)) continue

        j = heystack.indexOf(l, j + 1)
        if (j === -1)
          return false
      }
      return true
    })
  }
}

export function debounce(func, wait, immediate) {
  var timeout;
  return function() {
    var context = this, args = arguments;
    var later = function() {
      timeout = null;
      if (!immediate) func.apply(context, args);
    };
    var callNow = immediate && !timeout;
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
    if (callNow) func.apply(context, args);
  };
};