/* Fixture for the COFF loader tests: a real object file produced by mingw,
 * shaped like a BOF (entry symbol `go`, extern BeaconOutput). */
typedef void (*BeaconOutput_t)(int type, const char *data, int len);
extern void BeaconOutput(int type, char *data, int len);

void go(char *args, int len) {
    BeaconOutput(0, "sample-bof-output\n", 18);
}
