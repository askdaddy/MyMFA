export { DomainError } from './errors.js'
export { SORT_MODES, sortEntries } from './sort.js'
export type { SortMode, SortOptions } from './sort.js'
export {
  MAX_POSITION_LENGTH,
  keyBetween,
  rebalancePositions,
  appendEntry,
  moveEntry,
  moveTag,
} from './positions.js'
export { addTag, updateTag, deleteTag } from './tags.js'
export { filterEntries } from './filter.js'
export type { FilterOptions } from './filter.js'
export { searchEntries } from './search.js'
export type { SearchOptions, SearchResult } from './search.js'
export { recordUsage, setFavorite } from './usage.js'
export type { UsageEvent } from './usage.js'
export { normalizeHostname, matchesSite, matchingEntries } from './sites.js'
export type { SiteContext } from './sites.js'
