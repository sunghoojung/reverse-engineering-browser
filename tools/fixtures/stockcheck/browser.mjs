// Project-authored fixture code. This is not extracted or captured JavaScript.
export function lookupKey(sku, variant, store, catalogVersion) {
  const input = [catalogVersion, store, variant, sku].join('|');
  return btoa(input).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

export function mountStockcheck(document, {fetchImpl = fetch} = {}) {
  const field = id => document.getElementById(id);
  const button = field('check-stock'), result = field('stock-result');
  // The test invokes this actual authored handler through a DOM stub. A real
  // browser run is a separate lane; neither is represented as native evidence.
  const check = async () => {
    button.disabled = true;
    result.textContent = 'Checking…';
    const sku = field('sku').value, variant = field('variant').value, store = field('store').value;
    const catalogVersion = field('catalog-version').value;
    try {
      const response = await fetchImpl('/api/stock', {
        method: 'POST', credentials: 'omit', redirect: 'manual',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({sku, variant, store, catalog_version: catalogVersion,
          lookup_key: lookupKey(sku, variant, store, catalogVersion)}),
      });
      const value = await response.json();
      result.textContent = response.ok ? JSON.stringify(value) : `HTTP ${response.status}: ${value.code}`;
    } catch {
      result.textContent = 'Stock result unavailable';
    } finally {
      button.disabled = false;
    }
  };
  button.addEventListener('click', check);
  return () => button.removeEventListener('click', check);
}

if (typeof document !== 'undefined') mountStockcheck(document);
