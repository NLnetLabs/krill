import axios from 'axios'

const apiClient = axios.create({
  withCredentials: false,
  headers: {
    Accept: 'application/json',
    'Content-Type': 'application/json',
    'Authorization': 'Bearer secret'
  }
})

export default {
  getPublishers() {
    return apiClient.get('/api/v1/publishers')
  }
}