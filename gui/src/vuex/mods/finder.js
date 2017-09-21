import * as types from '~/vuex/types'


export const state = {
  root: '',
}


export const getters = {
  [types.FINDER_ROOT]: state => state.root,
}


export const mutations = {
  [types.FINDER_ROOT]: (state, root) => state.root = root,
}

