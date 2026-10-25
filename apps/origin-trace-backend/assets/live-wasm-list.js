function () {
  const objects = [];
  for (let index = 0; index < this.length && index < 32; index++) {
    objects[index] = this[index];
  }
  return objects;
}
