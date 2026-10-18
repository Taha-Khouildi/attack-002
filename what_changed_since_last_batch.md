# What changed since the last batch

The earlier local examples used weaker values: the constant Bias sample used a
`+0.005` offset, and the Spike sample used signed magnitudes between `-0.005`
and `+0.005`. Results previously shared with the AI team were obtained using
that weaker sample.

The new `provisional_v2` JSON profile records a positive Bias offset range of
`+0.02` to `+0.08`, with a duration of 6–72 consecutive hourly readings. These
values are provisional placeholders, not a final scenario specification.
No new batch has been generated, so this change makes no claim about detector
performance. The Spike magnitude placeholder is `+0.03` to `+0.10`, but Spike
is disabled until its required duration and spike-count ranges are specified.

No held-out allocation plan with event counts or per-station allocation was
found in the repository. Held-out data was not generated or included in this
provisional profile.
