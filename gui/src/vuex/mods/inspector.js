import * as types from '~/vuex/types'


export const state = {
  socket: null,
}


export const getters = {
  [types.GET_SOCKET]: state => state.socket,
}


export const mutations = {
  [types.STORE_SOCKET]: (state, socket) => {
    socket.call = (function(event, data) {
      return new Promise((resolve, reject) => {
        let ok = false
        this.emit(event, data, response => {
          console.log(response)
          if (response.status === 'ok') {
            ok = true
            resolve(response.data)
          } else {
            reject(response.error)
          }
        })

        setTimeout(() => {
          if (!ok)
            reject('Request timed out')
        }, 5000)
      })
    }).bind(socket)
    state.socket = socket
  },
}

