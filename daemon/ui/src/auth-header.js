export function authHeader() {
  let user = JSON.parse(localStorage.getItem('user'));
  let headers = {
    'Accept': 'application/json',
    'Content-Type': 'application/json',
    'Authorization': 'Bearer secret'
  }
  if (user && user.authdata) {
    headers.Authorization = 'Bearer ' + window.atob(user.authdata);
  }
  return headers;
}