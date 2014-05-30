#ifndef HOOK_H
#define HOOK_H

void hijack_start(void *target, void *new);
void hijack_pause(void *target);
void hijack_resume(void *target);
void hijack_stop(void *target);

#endif // HOOK_H