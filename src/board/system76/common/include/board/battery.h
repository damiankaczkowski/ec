#ifndef _BOARD_BATTERY_H
#define _BOARD_BATTERY_H

#include <stdbool.h>
#include <stdint.h>

extern uint16_t battery_temp;
extern uint16_t battery_voltage;
extern uint16_t battery_current;
extern uint16_t battery_charge;
extern uint16_t battery_remaining_capacity;
extern uint16_t battery_full_capacity;
extern uint16_t battery_status;
extern uint16_t battery_design_capacity;
extern uint16_t battery_design_voltage;

void battery_init(void);
int battery_charger_disable(void);
int battery_charger_enable(void);
void battery_event(void);
void battery_debug(void);

/**
 * Configure the charger based on charging threshold values.
 */
int battery_charger_configure(void);

int battery_get_start_threshold(void);
int battery_get_stop_threshold(void);
bool battery_set_start_threshold(int32_t value);
bool battery_set_stop_threshold(int32_t value);

#endif // _BOARD_BATTERY_H
