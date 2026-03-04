#pragma once

void MoveToPosition(int x, int y);
void StopAutoWalk();
void ChangeServerLine(int line);

// 挤线状态机tick (每帧调用)
void NavigationTick();
