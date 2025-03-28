import pstats
ps = pstats.Stats('profile_stats_benign_chunk_115.prof')
ps.sort_stats('cumulative').print_stats(10)