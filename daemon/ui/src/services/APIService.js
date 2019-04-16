import axios from 'axios';
import {
  authHeader
} from '../auth-header'

const apiClient = axios.create({
  withCredentials: false,
  headers: authHeader()
})

export default {
  login(token) {
    return apiClient.post('/ui/login', {
      token: token
    }).then(response => {
      if (response.status === 200) {
        let user = {
          authdata: window.btoa(token)
        }
        localStorage.setItem('user', JSON.stringify(user));
      }
      return response;
    });

  },
  logout() {
    localStorage.removeItem('user');
    return apiClient.post('/ui/logout');
  },
  getPublishers() {
    return apiClient.get('/api/v1/publishers')
  },
  getPublisher(handle) {
    return apiClient.get('/api/v1/publishers/' + handle);
  },
  getPublisherData(handle) {
    return apiClient.get('/publication/' + handle);
  },
  retirePublisher(handle) {
    return apiClient.delete('/api/v1/publishers/' + handle);
  },
  getEndpoint(uri) {
    return apiClient.get(uri);
  },
  addPublisher(handle, uri, token) {
    return apiClient.post('/api/v1/publishers', {
      handle: handle,
      base_uri: uri,
      token: token
    }).catch(function(error) {
      if (error.response && error.response.data) {
        return Promise.reject({
          data: error.response.data
        });
      }
      return Promise.reject({
        data: {
          code: -1
        }
      });
    })
  }
}