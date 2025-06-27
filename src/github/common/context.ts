import { AsyncLocalStorage } from 'async_hooks';

export const authStorage = new AsyncLocalStorage<{ token?: string }>();
