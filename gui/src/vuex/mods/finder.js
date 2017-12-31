import * as types from '~/vuex/types'


export const state = {
  root: '',
  downloading: false,
  bytes: 0,
  total: 0,
}


export const getters = {
  [types.FINDER_ROOT]: state => state.root,
  [types.DOWNLOADING]: state => state.downloading,
  [types.PROGRESS]: state => (state.bytes * 100 / state.total).toFixed(2),
  [types.DOWNLOAD_TOTAL_SIZE]: state => state.total,
  [types.DOWNLOADED_SIZE]: state => state.bytes,
}


export const mutations = {
  [types.FINDER_ROOT]: (state, root) => state.root = root,
  [types.DOWNLOADING]: (state, downloading) => state.downloading = downloading,
  [types.SET_DOWNLOAD_TOTAL]: (state, total) => {
    state.bytes = 0
    state.total = total
  },
  [types.UPDATE_BYTES]: (state, bytes) => state.bytes += bytes,
}
