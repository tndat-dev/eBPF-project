# AIMS counterbalanced overhead

| Effect | Throughput loss | 95% block CI | p99 increase | 95% block CI |
|---|---:|---:|---:|---:|
| tetragon_vs_no_tracing | -1.698% | [-3.9547975215543762, 1.9087943801325724] | 1.321% | [-4.002415783671065, 8.673721001577716] |
| full_pipeline_vs_no_tracing | -1.545% | [-3.930223860055848, 1.3759570181199665] | 2.702% | [-2.2486331126253143, 4.766670207144996] |
| detector_increment_vs_tetragon | 0.245% | [-4.293487309094335, 3.5208566996435824] | 0.573% | [-8.286396096932314, 7.900506247793571] |

CI bootstrap theo sáu phase-order block đã ghép cặp.
