package net.eneiluj.moneybuster.android.quicksettings;

import android.annotation.TargetApi;
import android.content.Intent;
import android.os.Build;
import android.service.quicksettings.Tile;
import android.service.quicksettings.TileService;

import net.eneiluj.moneybuster.android.activity.NewProjectActivity;

/**
 * This {@link TileService} adds a quick settings tile that leads to the new project view.
 */
@TargetApi(Build.VERSION_CODES.N)
public class NewProjectTileService extends TileService {

    @Override
    public void onStartListening() {
        Tile tile = getQsTile();
        tile.setState(Tile.STATE_ACTIVE);

        tile.updateTile();
    }

    @Override
    public void onClick() {
        // create new project intent
        final Intent newProjectIntent = new Intent(getApplicationContext(), NewProjectActivity.class);
        // ensure it won't open twice if already running
        newProjectIntent.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_NEW_TASK);

        // ask to unlock the screen if locked, then start new project intent
        unlockAndRun(new Runnable() {
            @Override
            public void run() {
                startActivityAndCollapse(newProjectIntent);
            }
        });

    }
}
